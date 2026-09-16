rule TTP_XOR_QUAD_CurrentVersionRun_fc19 {
  strings:
    $key_fc19 = { af 76 [2] 8b 78 [2] a0 54 [2] 8e 76 [2] 9a 6d [2] 95 77 [2] 8b 6a [2] 89 6b [2] 92 6d [2] 8e 6a [2] 92 45 }

  condition:
    any of them
}