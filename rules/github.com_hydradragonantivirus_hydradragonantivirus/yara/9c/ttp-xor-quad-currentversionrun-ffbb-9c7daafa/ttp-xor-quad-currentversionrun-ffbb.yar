rule TTP_XOR_QUAD_CurrentVersionRun_ffbb {
  strings:
    $key_ffbb = { ac d4 [2] 88 da [2] a3 f6 [2] 8d d4 [2] 99 cf [2] 96 d5 [2] 88 c8 [2] 8a c9 [2] 91 cf [2] 8d c8 [2] 91 e7 }

  condition:
    any of them
}