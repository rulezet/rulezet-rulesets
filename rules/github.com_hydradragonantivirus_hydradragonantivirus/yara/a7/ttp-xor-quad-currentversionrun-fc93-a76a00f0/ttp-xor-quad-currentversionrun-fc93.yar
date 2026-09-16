rule TTP_XOR_QUAD_CurrentVersionRun_fc93 {
  strings:
    $key_fc93 = { af fc [2] 8b f2 [2] a0 de [2] 8e fc [2] 9a e7 [2] 95 fd [2] 8b e0 [2] 89 e1 [2] 92 e7 [2] 8e e0 [2] 92 cf }

  condition:
    any of them
}