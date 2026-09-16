rule TTP_XOR_WriteProcessMemory_5f4f {
  strings:
    $key_5f4f = { 08 3d [2] 3a 1f [2] 3c 2a [2] 12 2a [2] 2d 36 }

  condition:
    any of them
}