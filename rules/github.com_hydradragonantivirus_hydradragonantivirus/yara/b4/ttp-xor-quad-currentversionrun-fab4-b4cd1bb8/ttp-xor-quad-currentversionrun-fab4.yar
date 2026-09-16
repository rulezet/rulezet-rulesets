rule TTP_XOR_QUAD_CurrentVersionRun_fab4 {
  strings:
    $key_fab4 = { a9 db [2] 8d d5 [2] a6 f9 [2] 88 db [2] 9c c0 [2] 93 da [2] 8d c7 [2] 8f c6 [2] 94 c0 [2] 88 c7 [2] 94 e8 }

  condition:
    any of them
}