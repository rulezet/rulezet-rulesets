rule TTP_XOR_WriteProcessMemory_66ee {
  strings:
    $key_66ee = { 31 9c [2] 03 be [2] 05 8b [2] 2b 8b [2] 14 97 }

  condition:
    any of them
}