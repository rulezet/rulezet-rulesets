rule TTP_XOR_WriteProcessMemory_17d3 {
  strings:
    $key_17d3 = { 40 a1 [2] 72 83 [2] 74 b6 [2] 5a b6 [2] 65 aa }

  condition:
    any of them
}