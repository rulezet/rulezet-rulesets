rule TTP_XOR_QUAD_CurrentVersionRun_6abb {
  strings:
    $key_6abb = { 39 d4 [2] 1d da [2] 36 f6 [2] 18 d4 [2] 0c cf [2] 03 d5 [2] 1d c8 [2] 1f c9 [2] 04 cf [2] 18 c8 [2] 04 e7 }

  condition:
    any of them
}