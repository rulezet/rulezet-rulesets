rule TTP_XOR_WriteProcessMemory_f17d {
  strings:
    $key_f17d = { a6 0f [2] 94 2d [2] 92 18 [2] bc 18 [2] 83 04 }

  condition:
    any of them
}