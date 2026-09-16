rule TTP_XOR_QUAD_CurrentVersionRun_fc3f {
  strings:
    $key_fc3f = { af 50 [2] 8b 5e [2] a0 72 [2] 8e 50 [2] 9a 4b [2] 95 51 [2] 8b 4c [2] 89 4d [2] 92 4b [2] 8e 4c [2] 92 63 }

  condition:
    any of them
}