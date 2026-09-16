rule TTP_XOR_WriteProcessMemory_572f {
  strings:
    $key_572f = { 00 5d [2] 32 7f [2] 34 4a [2] 1a 4a [2] 25 56 }

  condition:
    any of them
}