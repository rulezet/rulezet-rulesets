rule TTP_XOR_QUAD_CurrentVersionRun_43a6 {
  strings:
    $key_43a6 = { 10 c9 [2] 34 c7 [2] 1f eb [2] 31 c9 [2] 25 d2 [2] 2a c8 [2] 34 d5 [2] 36 d4 [2] 2d d2 [2] 31 d5 [2] 2d fa }

  condition:
    any of them
}