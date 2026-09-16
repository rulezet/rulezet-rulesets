rule TTP_XOR_QUAD_CurrentVersionRun_fa97 {
  strings:
    $key_fa97 = { a9 f8 [2] 8d f6 [2] a6 da [2] 88 f8 [2] 9c e3 [2] 93 f9 [2] 8d e4 [2] 8f e5 [2] 94 e3 [2] 88 e4 [2] 94 cb }

  condition:
    any of them
}