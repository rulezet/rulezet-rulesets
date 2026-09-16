rule TTP_XOR_WriteProcessMemory_636f {
  strings:
    $key_636f = { 34 1d [2] 06 3f [2] 00 0a [2] 2e 0a [2] 11 16 }

  condition:
    any of them
}