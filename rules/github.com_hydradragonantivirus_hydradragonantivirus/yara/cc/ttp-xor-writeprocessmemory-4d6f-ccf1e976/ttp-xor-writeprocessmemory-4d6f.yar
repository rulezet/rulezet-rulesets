rule TTP_XOR_WriteProcessMemory_4d6f {
  strings:
    $key_4d6f = { 1a 1d [2] 28 3f [2] 2e 0a [2] 00 0a [2] 3f 16 }

  condition:
    any of them
}