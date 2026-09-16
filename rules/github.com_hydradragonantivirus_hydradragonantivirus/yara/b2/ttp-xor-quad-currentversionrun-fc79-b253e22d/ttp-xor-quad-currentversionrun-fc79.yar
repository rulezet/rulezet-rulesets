rule TTP_XOR_QUAD_CurrentVersionRun_fc79 {
  strings:
    $key_fc79 = { af 16 [2] 8b 18 [2] a0 34 [2] 8e 16 [2] 9a 0d [2] 95 17 [2] 8b 0a [2] 89 0b [2] 92 0d [2] 8e 0a [2] 92 25 }

  condition:
    any of them
}