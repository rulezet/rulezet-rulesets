rule TTP_XOR_QUAD_CurrentVersionRun_fc71 {
  strings:
    $key_fc71 = { af 1e [2] 8b 10 [2] a0 3c [2] 8e 1e [2] 9a 05 [2] 95 1f [2] 8b 02 [2] 89 03 [2] 92 05 [2] 8e 02 [2] 92 2d }

  condition:
    any of them
}