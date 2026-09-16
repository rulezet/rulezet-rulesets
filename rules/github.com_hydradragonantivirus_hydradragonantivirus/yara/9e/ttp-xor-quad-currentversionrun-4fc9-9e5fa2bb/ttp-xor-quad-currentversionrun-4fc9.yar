rule TTP_XOR_QUAD_CurrentVersionRun_4fc9 {
  strings:
    $key_4fc9 = { 1c a6 [2] 38 a8 [2] 13 84 [2] 3d a6 [2] 29 bd [2] 26 a7 [2] 38 ba [2] 3a bb [2] 21 bd [2] 3d ba [2] 21 95 }

  condition:
    any of them
}