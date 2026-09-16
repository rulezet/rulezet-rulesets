rule TTP_XOR_WriteProcessMemory_4ae1 {
  strings:
    $key_4ae1 = { 1d 93 [2] 2f b1 [2] 29 84 [2] 07 84 [2] 38 98 }

  condition:
    any of them
}