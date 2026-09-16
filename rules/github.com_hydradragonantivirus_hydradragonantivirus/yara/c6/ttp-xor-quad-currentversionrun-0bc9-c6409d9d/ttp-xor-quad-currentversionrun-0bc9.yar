rule TTP_XOR_QUAD_CurrentVersionRun_0bc9 {
  strings:
    $key_0bc9 = { 58 a6 [2] 7c a8 [2] 57 84 [2] 79 a6 [2] 6d bd [2] 62 a7 [2] 7c ba [2] 7e bb [2] 65 bd [2] 79 ba [2] 65 95 }

  condition:
    any of them
}