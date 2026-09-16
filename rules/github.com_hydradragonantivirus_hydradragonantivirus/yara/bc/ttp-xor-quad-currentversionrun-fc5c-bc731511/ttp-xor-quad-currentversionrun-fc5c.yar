rule TTP_XOR_QUAD_CurrentVersionRun_fc5c {
  strings:
    $key_fc5c = { af 33 [2] 8b 3d [2] a0 11 [2] 8e 33 [2] 9a 28 [2] 95 32 [2] 8b 2f [2] 89 2e [2] 92 28 [2] 8e 2f [2] 92 00 }

  condition:
    any of them
}