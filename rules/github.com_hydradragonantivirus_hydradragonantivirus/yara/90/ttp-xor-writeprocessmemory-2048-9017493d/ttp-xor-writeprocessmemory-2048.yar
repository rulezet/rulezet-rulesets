rule TTP_XOR_WriteProcessMemory_2048 {
  strings:
    $key_2048 = { 77 3a [2] 45 18 [2] 43 2d [2] 6d 2d [2] 52 31 }

  condition:
    any of them
}