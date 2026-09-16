rule TTP_XOR_QUAD_CurrentVersionRun_274b {
  strings:
    $key_274b = { 74 24 [2] 50 2a [2] 7b 06 [2] 55 24 [2] 41 3f [2] 4e 25 [2] 50 38 [2] 52 39 [2] 49 3f [2] 55 38 [2] 49 17 }

  condition:
    any of them
}