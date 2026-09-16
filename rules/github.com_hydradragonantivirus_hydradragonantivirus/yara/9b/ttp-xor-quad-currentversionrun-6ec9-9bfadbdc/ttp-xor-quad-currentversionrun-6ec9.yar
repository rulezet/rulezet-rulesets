rule TTP_XOR_QUAD_CurrentVersionRun_6ec9 {
  strings:
    $key_6ec9 = { 3d a6 [2] 19 a8 [2] 32 84 [2] 1c a6 [2] 08 bd [2] 07 a7 [2] 19 ba [2] 1b bb [2] 00 bd [2] 1c ba [2] 00 95 }

  condition:
    any of them
}