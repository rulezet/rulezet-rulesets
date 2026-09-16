rule TTP_XOR_QUAD_CurrentVersionRun_fc4f {
  strings:
    $key_fc4f = { af 20 [2] 8b 2e [2] a0 02 [2] 8e 20 [2] 9a 3b [2] 95 21 [2] 8b 3c [2] 89 3d [2] 92 3b [2] 8e 3c [2] 92 13 }

  condition:
    any of them
}