rule TTP_XOR_QUAD_CurrentVersionRun_facf {
  strings:
    $key_facf = { a9 a0 [2] 8d ae [2] a6 82 [2] 88 a0 [2] 9c bb [2] 93 a1 [2] 8d bc [2] 8f bd [2] 94 bb [2] 88 bc [2] 94 93 }

  condition:
    any of them
}