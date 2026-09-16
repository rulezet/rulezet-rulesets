rule TTP_XOR_QUAD_CurrentVersionRun_fc50 {
  strings:
    $key_fc50 = { af 3f [2] 8b 31 [2] a0 1d [2] 8e 3f [2] 9a 24 [2] 95 3e [2] 8b 23 [2] 89 22 [2] 92 24 [2] 8e 23 [2] 92 0c }

  condition:
    any of them
}