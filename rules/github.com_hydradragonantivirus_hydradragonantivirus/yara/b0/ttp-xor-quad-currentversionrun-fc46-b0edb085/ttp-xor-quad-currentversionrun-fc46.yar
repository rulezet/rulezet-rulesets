rule TTP_XOR_QUAD_CurrentVersionRun_fc46 {
  strings:
    $key_fc46 = { af 29 [2] 8b 27 [2] a0 0b [2] 8e 29 [2] 9a 32 [2] 95 28 [2] 8b 35 [2] 89 34 [2] 92 32 [2] 8e 35 [2] 92 1a }

  condition:
    any of them
}