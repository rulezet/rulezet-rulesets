rule TTP_XOR_WriteProcessMemory_6a5f {
  strings:
    $key_6a5f = { 3d 2d [2] 0f 0f [2] 09 3a [2] 27 3a [2] 18 26 }

  condition:
    any of them
}