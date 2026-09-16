rule TTP_XOR_WriteProcessMemory_5048 {
  strings:
    $key_5048 = { 07 3a [2] 35 18 [2] 33 2d [2] 1d 2d [2] 22 31 }

  condition:
    any of them
}