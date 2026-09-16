rule TTP_XOR_WriteProcessMemory_0748 {
  strings:
    $key_0748 = { 50 3a [2] 62 18 [2] 64 2d [2] 4a 2d [2] 75 31 }

  condition:
    any of them
}