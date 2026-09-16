rule TTP_XOR_WriteProcessMemory_50ee {
  strings:
    $key_50ee = { 07 9c [2] 35 be [2] 33 8b [2] 1d 8b [2] 22 97 }

  condition:
    any of them
}