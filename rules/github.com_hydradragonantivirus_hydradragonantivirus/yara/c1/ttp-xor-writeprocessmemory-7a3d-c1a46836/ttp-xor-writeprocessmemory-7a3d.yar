rule TTP_XOR_WriteProcessMemory_7a3d {
  strings:
    $key_7a3d = { 2d 4f [2] 1f 6d [2] 19 58 [2] 37 58 [2] 08 44 }

  condition:
    any of them
}