rule TTP_XOR_QUAD_CurrentVersionRun_fc7c {
  strings:
    $key_fc7c = { af 13 [2] 8b 1d [2] a0 31 [2] 8e 13 [2] 9a 08 [2] 95 12 [2] 8b 0f [2] 89 0e [2] 92 08 [2] 8e 0f [2] 92 20 }

  condition:
    any of them
}