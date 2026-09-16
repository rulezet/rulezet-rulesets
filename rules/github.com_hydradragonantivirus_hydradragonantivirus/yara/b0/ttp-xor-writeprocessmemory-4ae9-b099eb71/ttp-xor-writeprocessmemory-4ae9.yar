rule TTP_XOR_WriteProcessMemory_4ae9 {
  strings:
    $key_4ae9 = { 1d 9b [2] 2f b9 [2] 29 8c [2] 07 8c [2] 38 90 }

  condition:
    any of them
}