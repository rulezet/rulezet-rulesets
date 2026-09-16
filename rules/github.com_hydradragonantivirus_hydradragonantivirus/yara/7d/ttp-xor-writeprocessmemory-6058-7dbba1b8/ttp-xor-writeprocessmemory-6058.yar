rule TTP_XOR_WriteProcessMemory_6058 {
  strings:
    $key_6058 = { 37 2a [2] 05 08 [2] 03 3d [2] 2d 3d [2] 12 21 }

  condition:
    any of them
}