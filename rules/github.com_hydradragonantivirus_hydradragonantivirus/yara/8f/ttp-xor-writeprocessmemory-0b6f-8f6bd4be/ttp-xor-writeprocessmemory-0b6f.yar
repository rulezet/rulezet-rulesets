rule TTP_XOR_WriteProcessMemory_0b6f {
  strings:
    $key_0b6f = { 5c 1d [2] 6e 3f [2] 68 0a [2] 46 0a [2] 79 16 }

  condition:
    any of them
}