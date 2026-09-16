rule TTP_XOR_QUAD_CurrentVersionRun_fcea {
  strings:
    $key_fcea = { af 85 [2] 8b 8b [2] a0 a7 [2] 8e 85 [2] 9a 9e [2] 95 84 [2] 8b 99 [2] 89 98 [2] 92 9e [2] 8e 99 [2] 92 b6 }

  condition:
    any of them
}