rule TTP_XOR_WriteProcessMemory_304d {
  strings:
    $key_304d = { 67 3f [2] 55 1d [2] 53 28 [2] 7d 28 [2] 42 34 }

  condition:
    any of them
}