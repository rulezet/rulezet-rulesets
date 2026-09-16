rule TTP_XOR_QUAD_CurrentVersionRun_fabb {
  strings:
    $key_fabb = { a9 d4 [2] 8d da [2] a6 f6 [2] 88 d4 [2] 9c cf [2] 93 d5 [2] 8d c8 [2] 8f c9 [2] 94 cf [2] 88 c8 [2] 94 e7 }

  condition:
    any of them
}