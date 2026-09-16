rule TTP_XOR_QUAD_CurrentVersionRun_fc37 {
  strings:
    $key_fc37 = { af 58 [2] 8b 56 [2] a0 7a [2] 8e 58 [2] 9a 43 [2] 95 59 [2] 8b 44 [2] 89 45 [2] 92 43 [2] 8e 44 [2] 92 6b }

  condition:
    any of them
}