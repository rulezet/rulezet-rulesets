rule TTP_XOR_WriteProcessMemory_4e4f {
  strings:
    $key_4e4f = { 19 3d [2] 2b 1f [2] 2d 2a [2] 03 2a [2] 3c 36 }

  condition:
    any of them
}