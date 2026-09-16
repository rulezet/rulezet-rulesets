rule TTP_XOR_QUAD_CurrentVersionRun_fc7f {
  strings:
    $key_fc7f = { af 10 [2] 8b 1e [2] a0 32 [2] 8e 10 [2] 9a 0b [2] 95 11 [2] 8b 0c [2] 89 0d [2] 92 0b [2] 8e 0c [2] 92 23 }

  condition:
    any of them
}