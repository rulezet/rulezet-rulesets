rule TTP_XOR_QUAD_CurrentVersionRun_5fc9 {
  strings:
    $key_5fc9 = { 0c a6 [2] 28 a8 [2] 03 84 [2] 2d a6 [2] 39 bd [2] 36 a7 [2] 28 ba [2] 2a bb [2] 31 bd [2] 2d ba [2] 31 95 }

  condition:
    any of them
}