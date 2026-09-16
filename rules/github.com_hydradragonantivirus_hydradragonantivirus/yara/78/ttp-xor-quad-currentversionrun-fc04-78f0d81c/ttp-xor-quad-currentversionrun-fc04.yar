rule TTP_XOR_QUAD_CurrentVersionRun_fc04 {
  strings:
    $key_fc04 = { af 6b [2] 8b 65 [2] a0 49 [2] 8e 6b [2] 9a 70 [2] 95 6a [2] 8b 77 [2] 89 76 [2] 92 70 [2] 8e 77 [2] 92 58 }

  condition:
    any of them
}