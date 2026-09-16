rule TTP_XOR_WriteProcessMemory_074d {
  strings:
    $key_074d = { 50 3f [2] 62 1d [2] 64 28 [2] 4a 28 [2] 75 34 }

  condition:
    any of them
}