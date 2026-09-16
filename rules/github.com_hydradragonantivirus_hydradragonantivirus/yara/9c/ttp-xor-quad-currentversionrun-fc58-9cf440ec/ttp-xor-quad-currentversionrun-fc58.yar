rule TTP_XOR_QUAD_CurrentVersionRun_fc58 {
  strings:
    $key_fc58 = { af 37 [2] 8b 39 [2] a0 15 [2] 8e 37 [2] 9a 2c [2] 95 36 [2] 8b 2b [2] 89 2a [2] 92 2c [2] 8e 2b [2] 92 04 }

  condition:
    any of them
}