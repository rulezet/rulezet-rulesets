rule TTP_XOR_QUAD_CurrentVersionRun_7fc9 {
  strings:
    $key_7fc9 = { 2c a6 [2] 08 a8 [2] 23 84 [2] 0d a6 [2] 19 bd [2] 16 a7 [2] 08 ba [2] 0a bb [2] 11 bd [2] 0d ba [2] 11 95 }

  condition:
    any of them
}