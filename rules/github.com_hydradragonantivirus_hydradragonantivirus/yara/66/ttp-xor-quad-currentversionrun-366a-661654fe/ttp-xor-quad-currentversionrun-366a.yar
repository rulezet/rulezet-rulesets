rule TTP_XOR_QUAD_CurrentVersionRun_366a {
  strings:
    $key_366a = { 65 05 [2] 41 0b [2] 6a 27 [2] 44 05 [2] 50 1e [2] 5f 04 [2] 41 19 [2] 43 18 [2] 58 1e [2] 44 19 [2] 58 36 }

  condition:
    any of them
}