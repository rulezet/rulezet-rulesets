rule TTP_XOR_WriteProcessMemory_7a4f {
  strings:
    $key_7a4f = { 2d 3d [2] 1f 1f [2] 19 2a [2] 37 2a [2] 08 36 }

  condition:
    any of them
}