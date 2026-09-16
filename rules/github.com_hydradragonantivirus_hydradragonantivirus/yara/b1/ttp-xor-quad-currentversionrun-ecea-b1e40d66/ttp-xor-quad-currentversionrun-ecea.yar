rule TTP_XOR_QUAD_CurrentVersionRun_ecea {
  strings:
    $key_ecea = { bf 85 [2] 9b 8b [2] b0 a7 [2] 9e 85 [2] 8a 9e [2] 85 84 [2] 9b 99 [2] 99 98 [2] 82 9e [2] 9e 99 [2] 82 b6 }

  condition:
    any of them
}