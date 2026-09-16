rule TTP_XOR_QUAD_CurrentVersionRun_fc09 {
  strings:
    $key_fc09 = { af 66 [2] 8b 68 [2] a0 44 [2] 8e 66 [2] 9a 7d [2] 95 67 [2] 8b 7a [2] 89 7b [2] 92 7d [2] 8e 7a [2] 92 55 }

  condition:
    any of them
}