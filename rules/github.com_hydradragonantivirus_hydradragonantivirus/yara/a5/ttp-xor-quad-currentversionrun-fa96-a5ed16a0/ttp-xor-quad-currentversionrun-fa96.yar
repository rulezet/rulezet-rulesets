rule TTP_XOR_QUAD_CurrentVersionRun_fa96 {
  strings:
    $key_fa96 = { a9 f9 [2] 8d f7 [2] a6 db [2] 88 f9 [2] 9c e2 [2] 93 f8 [2] 8d e5 [2] 8f e4 [2] 94 e2 [2] 88 e5 [2] 94 ca }

  condition:
    any of them
}