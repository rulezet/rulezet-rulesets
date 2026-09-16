rule TTP_XOR_QUAD_CurrentVersionRun_2a1a {
  strings:
    $key_2a1a = { 79 75 [2] 5d 7b [2] 76 57 [2] 58 75 [2] 4c 6e [2] 43 74 [2] 5d 69 [2] 5f 68 [2] 44 6e [2] 58 69 [2] 44 46 }

  condition:
    any of them
}