rule TTP_XOR_WriteProcessMemory_6f5f {
  strings:
    $key_6f5f = { 38 2d [2] 0a 0f [2] 0c 3a [2] 22 3a [2] 1d 26 }

  condition:
    any of them
}