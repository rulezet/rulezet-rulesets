rule TTP_XOR_QUAD_CurrentVersionRun_fc34 {
  strings:
    $key_fc34 = { af 5b [2] 8b 55 [2] a0 79 [2] 8e 5b [2] 9a 40 [2] 95 5a [2] 8b 47 [2] 89 46 [2] 92 40 [2] 8e 47 [2] 92 68 }

  condition:
    any of them
}