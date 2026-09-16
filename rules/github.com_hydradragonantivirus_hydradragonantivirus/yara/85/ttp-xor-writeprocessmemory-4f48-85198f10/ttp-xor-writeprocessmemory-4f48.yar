rule TTP_XOR_WriteProcessMemory_4f48 {
  strings:
    $key_4f48 = { 18 3a [2] 2a 18 [2] 2c 2d [2] 02 2d [2] 3d 31 }

  condition:
    any of them
}