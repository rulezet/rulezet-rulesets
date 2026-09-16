rule TTP_XOR_WriteProcessMemory_0b2f {
  strings:
    $key_0b2f = { 5c 5d [2] 6e 7f [2] 68 4a [2] 46 4a [2] 79 56 }

  condition:
    any of them
}