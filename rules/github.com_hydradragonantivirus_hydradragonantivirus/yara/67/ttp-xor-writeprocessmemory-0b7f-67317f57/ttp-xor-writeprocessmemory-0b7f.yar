rule TTP_XOR_WriteProcessMemory_0b7f {
  strings:
    $key_0b7f = { 5c 0d [2] 6e 2f [2] 68 1a [2] 46 1a [2] 79 06 }

  condition:
    any of them
}