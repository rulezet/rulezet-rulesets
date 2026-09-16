rule TTP_XOR_QUAD_CurrentVersionRun_91a6 {
  strings:
    $key_91a6 = { c2 c9 [2] e6 c7 [2] cd eb [2] e3 c9 [2] f7 d2 [2] f8 c8 [2] e6 d5 [2] e4 d4 [2] ff d2 [2] e3 d5 [2] ff fa }

  condition:
    any of them
}