rule TTP_XOR_QUAD_CurrentVersionRun_fe9c {
  strings:
    $key_fe9c = { ad f3 [2] 89 fd [2] a2 d1 [2] 8c f3 [2] 98 e8 [2] 97 f2 [2] 89 ef [2] 8b ee [2] 90 e8 [2] 8c ef [2] 90 c0 }

  condition:
    any of them
}