rule TTP_XOR_WriteProcessMemory_7a58 {
  strings:
    $key_7a58 = { 2d 2a [2] 1f 08 [2] 19 3d [2] 37 3d [2] 08 21 }

  condition:
    any of them
}