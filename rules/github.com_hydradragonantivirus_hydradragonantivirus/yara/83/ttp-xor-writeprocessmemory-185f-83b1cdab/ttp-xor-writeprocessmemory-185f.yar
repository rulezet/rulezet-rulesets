rule TTP_XOR_WriteProcessMemory_185f {
  strings:
    $key_185f = { 4f 2d [2] 7d 0f [2] 7b 3a [2] 55 3a [2] 6a 26 }

  condition:
    any of them
}