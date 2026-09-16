rule TTP_XOR_QUAD_CurrentVersionRun_5bc9 {
  strings:
    $key_5bc9 = { 08 a6 [2] 2c a8 [2] 07 84 [2] 29 a6 [2] 3d bd [2] 32 a7 [2] 2c ba [2] 2e bb [2] 35 bd [2] 29 ba [2] 35 95 }

  condition:
    any of them
}