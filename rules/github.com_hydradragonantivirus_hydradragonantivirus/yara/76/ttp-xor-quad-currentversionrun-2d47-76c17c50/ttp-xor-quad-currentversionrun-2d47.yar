rule TTP_XOR_QUAD_CurrentVersionRun_2d47 {
  strings:
    $key_2d47 = { 7e 28 [2] 5a 26 [2] 71 0a [2] 5f 28 [2] 4b 33 [2] 44 29 [2] 5a 34 [2] 58 35 [2] 43 33 [2] 5f 34 [2] 43 1b }

  condition:
    any of them
}