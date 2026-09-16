rule TTP_XOR_WriteProcessMemory_336f {
  strings:
    $key_336f = { 64 1d [2] 56 3f [2] 50 0a [2] 7e 0a [2] 41 16 }

  condition:
    any of them
}