rule TTP_XOR_WriteProcessMemory_50f9 {
  strings:
    $key_50f9 = { 07 8b [2] 35 a9 [2] 33 9c [2] 1d 9c [2] 22 80 }

  condition:
    any of them
}