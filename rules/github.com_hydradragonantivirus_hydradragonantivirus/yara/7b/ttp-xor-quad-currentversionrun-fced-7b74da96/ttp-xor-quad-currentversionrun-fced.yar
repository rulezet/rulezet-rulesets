rule TTP_XOR_QUAD_CurrentVersionRun_fced {
  strings:
    $key_fced = { af 82 [2] 8b 8c [2] a0 a0 [2] 8e 82 [2] 9a 99 [2] 95 83 [2] 8b 9e [2] 89 9f [2] 92 99 [2] 8e 9e [2] 92 b1 }

  condition:
    any of them
}