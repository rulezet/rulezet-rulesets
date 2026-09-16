rule TTP_XOR_QUAD_CurrentVersionRun_2d4b {
  strings:
    $key_2d4b = { 7e 24 [2] 5a 2a [2] 71 06 [2] 5f 24 [2] 4b 3f [2] 44 25 [2] 5a 38 [2] 58 39 [2] 43 3f [2] 5f 38 [2] 43 17 }

  condition:
    any of them
}