rule TTP_XOR_QUAD_CurrentVersionRun_fc23 {
  strings:
    $key_fc23 = { af 4c [2] 8b 42 [2] a0 6e [2] 8e 4c [2] 9a 57 [2] 95 4d [2] 8b 50 [2] 89 51 [2] 92 57 [2] 8e 50 [2] 92 7f }

  condition:
    any of them
}