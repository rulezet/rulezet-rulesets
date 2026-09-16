rule TTP_XOR_WriteProcessMemory_654d {
  strings:
    $key_654d = { 32 3f [2] 00 1d [2] 06 28 [2] 28 28 [2] 17 34 }

  condition:
    any of them
}