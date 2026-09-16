rule TTP_XOR_WriteProcessMemory_1c5f {
  strings:
    $key_1c5f = { 4b 2d [2] 79 0f [2] 7f 3a [2] 51 3a [2] 6e 26 }

  condition:
    any of them
}