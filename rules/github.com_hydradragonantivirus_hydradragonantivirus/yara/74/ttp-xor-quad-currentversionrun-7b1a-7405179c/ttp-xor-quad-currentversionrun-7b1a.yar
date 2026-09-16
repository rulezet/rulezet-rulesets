rule TTP_XOR_QUAD_CurrentVersionRun_7b1a {
  strings:
    $key_7b1a = { 28 75 [2] 0c 7b [2] 27 57 [2] 09 75 [2] 1d 6e [2] 12 74 [2] 0c 69 [2] 0e 68 [2] 15 6e [2] 09 69 [2] 15 46 }

  condition:
    any of them
}