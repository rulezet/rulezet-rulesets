rule TTP_XOR_WriteProcessMemory_63ee {
  strings:
    $key_63ee = { 34 9c [2] 06 be [2] 00 8b [2] 2e 8b [2] 11 97 }

  condition:
    any of them
}