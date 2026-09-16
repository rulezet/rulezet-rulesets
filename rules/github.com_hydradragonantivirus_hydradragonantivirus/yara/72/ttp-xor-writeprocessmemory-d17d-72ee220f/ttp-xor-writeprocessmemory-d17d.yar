rule TTP_XOR_WriteProcessMemory_d17d {
  strings:
    $key_d17d = { 86 0f [2] b4 2d [2] b2 18 [2] 9c 18 [2] a3 04 }

  condition:
    any of them
}