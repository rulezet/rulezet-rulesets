rule TTP_XOR_WriteProcessMemory_444d {
  strings:
    $key_444d = { 13 3f [2] 21 1d [2] 27 28 [2] 09 28 [2] 36 34 }

  condition:
    any of them
}