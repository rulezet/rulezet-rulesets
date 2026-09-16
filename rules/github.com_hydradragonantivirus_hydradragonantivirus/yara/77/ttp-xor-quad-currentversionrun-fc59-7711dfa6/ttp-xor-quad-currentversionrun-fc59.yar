rule TTP_XOR_QUAD_CurrentVersionRun_fc59 {
  strings:
    $key_fc59 = { af 36 [2] 8b 38 [2] a0 14 [2] 8e 36 [2] 9a 2d [2] 95 37 [2] 8b 2a [2] 89 2b [2] 92 2d [2] 8e 2a [2] 92 05 }

  condition:
    any of them
}