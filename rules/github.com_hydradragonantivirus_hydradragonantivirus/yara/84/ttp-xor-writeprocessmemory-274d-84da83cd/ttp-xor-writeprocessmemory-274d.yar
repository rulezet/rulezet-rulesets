rule TTP_XOR_WriteProcessMemory_274d {
  strings:
    $key_274d = { 70 3f [2] 42 1d [2] 44 28 [2] 6a 28 [2] 55 34 }

  condition:
    any of them
}