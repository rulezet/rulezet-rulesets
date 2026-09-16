rule TTP_XOR_QUAD_CurrentVersionRun_fc05 {
  strings:
    $key_fc05 = { af 6a [2] 8b 64 [2] a0 48 [2] 8e 6a [2] 9a 71 [2] 95 6b [2] 8b 76 [2] 89 77 [2] 92 71 [2] 8e 76 [2] 92 59 }

  condition:
    any of them
}