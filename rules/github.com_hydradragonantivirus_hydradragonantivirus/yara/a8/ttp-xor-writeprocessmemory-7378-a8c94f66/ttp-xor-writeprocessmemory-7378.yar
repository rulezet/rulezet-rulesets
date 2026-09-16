rule TTP_XOR_WriteProcessMemory_7378 {
  strings:
    $key_7378 = { 24 0a [2] 16 28 [2] 10 1d [2] 3e 1d [2] 01 01 }

  condition:
    any of them
}