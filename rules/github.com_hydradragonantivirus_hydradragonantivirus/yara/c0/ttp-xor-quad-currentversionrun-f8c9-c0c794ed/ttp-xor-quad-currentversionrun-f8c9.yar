rule TTP_XOR_QUAD_CurrentVersionRun_f8c9 {
  strings:
    $key_f8c9 = { ab a6 [2] 8f a8 [2] a4 84 [2] 8a a6 [2] 9e bd [2] 91 a7 [2] 8f ba [2] 8d bb [2] 96 bd [2] 8a ba [2] 96 95 }

  condition:
    any of them
}