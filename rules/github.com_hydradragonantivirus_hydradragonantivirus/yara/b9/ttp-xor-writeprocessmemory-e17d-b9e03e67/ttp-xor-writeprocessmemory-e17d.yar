rule TTP_XOR_WriteProcessMemory_e17d {
  strings:
    $key_e17d = { b6 0f [2] 84 2d [2] 82 18 [2] ac 18 [2] 93 04 }

  condition:
    any of them
}