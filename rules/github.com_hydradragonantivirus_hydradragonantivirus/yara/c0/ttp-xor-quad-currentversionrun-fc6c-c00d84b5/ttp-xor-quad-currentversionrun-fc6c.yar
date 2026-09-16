rule TTP_XOR_QUAD_CurrentVersionRun_fc6c {
  strings:
    $key_fc6c = { af 03 [2] 8b 0d [2] a0 21 [2] 8e 03 [2] 9a 18 [2] 95 02 [2] 8b 1f [2] 89 1e [2] 92 18 [2] 8e 1f [2] 92 30 }

  condition:
    any of them
}