rule TTP_XOR_QUAD_CurrentVersionRun_2d1b {
  strings:
    $key_2d1b = { 7e 74 [2] 5a 7a [2] 71 56 [2] 5f 74 [2] 4b 6f [2] 44 75 [2] 5a 68 [2] 58 69 [2] 43 6f [2] 5f 68 [2] 43 47 }

  condition:
    any of them
}