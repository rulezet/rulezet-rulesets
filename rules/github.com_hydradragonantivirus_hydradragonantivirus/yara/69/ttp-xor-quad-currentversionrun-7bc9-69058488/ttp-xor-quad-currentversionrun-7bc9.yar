rule TTP_XOR_QUAD_CurrentVersionRun_7bc9 {
  strings:
    $key_7bc9 = { 28 a6 [2] 0c a8 [2] 27 84 [2] 09 a6 [2] 1d bd [2] 12 a7 [2] 0c ba [2] 0e bb [2] 15 bd [2] 09 ba [2] 15 95 }

  condition:
    any of them
}