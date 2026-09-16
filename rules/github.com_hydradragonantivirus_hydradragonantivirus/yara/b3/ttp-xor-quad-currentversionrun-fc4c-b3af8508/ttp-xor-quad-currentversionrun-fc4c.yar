rule TTP_XOR_QUAD_CurrentVersionRun_fc4c {
  strings:
    $key_fc4c = { af 23 [2] 8b 2d [2] a0 01 [2] 8e 23 [2] 9a 38 [2] 95 22 [2] 8b 3f [2] 89 3e [2] 92 38 [2] 8e 3f [2] 92 10 }

  condition:
    any of them
}