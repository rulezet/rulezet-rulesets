rule TTP_XOR_WriteProcessMemory_5f6f {
  strings:
    $key_5f6f = { 08 1d [2] 3a 3f [2] 3c 0a [2] 12 0a [2] 2d 16 }

  condition:
    any of them
}