rule TTP_XOR_QUAD_CurrentVersionRun_4e1a {
  strings:
    $key_4e1a = { 1d 75 [2] 39 7b [2] 12 57 [2] 3c 75 [2] 28 6e [2] 27 74 [2] 39 69 [2] 3b 68 [2] 20 6e [2] 3c 69 [2] 20 46 }

  condition:
    any of them
}