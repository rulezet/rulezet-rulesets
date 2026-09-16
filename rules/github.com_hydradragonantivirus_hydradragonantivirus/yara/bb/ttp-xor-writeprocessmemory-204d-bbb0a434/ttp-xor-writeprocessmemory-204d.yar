rule TTP_XOR_WriteProcessMemory_204d {
  strings:
    $key_204d = { 77 3f [2] 45 1d [2] 43 28 [2] 6d 28 [2] 52 34 }

  condition:
    any of them
}