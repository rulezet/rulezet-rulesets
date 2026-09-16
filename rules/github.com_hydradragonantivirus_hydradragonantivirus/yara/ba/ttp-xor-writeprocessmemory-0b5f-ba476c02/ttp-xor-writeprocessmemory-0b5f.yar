rule TTP_XOR_WriteProcessMemory_0b5f {
  strings:
    $key_0b5f = { 5c 2d [2] 6e 0f [2] 68 3a [2] 46 3a [2] 79 26 }

  condition:
    any of them
}