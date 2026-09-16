rule TTP_XOR_QUAD_CurrentVersionRun_2d1a {
  strings:
    $key_2d1a = { 7e 75 [2] 5a 7b [2] 71 57 [2] 5f 75 [2] 4b 6e [2] 44 74 [2] 5a 69 [2] 58 68 [2] 43 6e [2] 5f 69 [2] 43 46 }

  condition:
    any of them
}