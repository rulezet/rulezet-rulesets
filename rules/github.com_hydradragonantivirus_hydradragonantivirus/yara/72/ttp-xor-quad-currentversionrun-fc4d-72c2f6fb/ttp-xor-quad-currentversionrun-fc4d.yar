rule TTP_XOR_QUAD_CurrentVersionRun_fc4d {
  strings:
    $key_fc4d = { af 22 [2] 8b 2c [2] a0 00 [2] 8e 22 [2] 9a 39 [2] 95 23 [2] 8b 3e [2] 89 3f [2] 92 39 [2] 8e 3e [2] 92 11 }

  condition:
    any of them
}