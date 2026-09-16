rule TTP_XOR_WriteProcessMemory_25ee {
  strings:
    $key_25ee = { 72 9c [2] 40 be [2] 46 8b [2] 68 8b [2] 57 97 }

  condition:
    any of them
}