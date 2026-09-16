rule TTP_XOR_QUAD_CurrentVersionRun_fc61 {
  strings:
    $key_fc61 = { af 0e [2] 8b 00 [2] a0 2c [2] 8e 0e [2] 9a 15 [2] 95 0f [2] 8b 12 [2] 89 13 [2] 92 15 [2] 8e 12 [2] 92 3d }

  condition:
    any of them
}