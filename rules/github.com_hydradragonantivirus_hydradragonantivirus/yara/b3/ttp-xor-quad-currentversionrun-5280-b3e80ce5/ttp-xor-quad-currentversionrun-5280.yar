rule TTP_XOR_QUAD_CurrentVersionRun_5280 {
  strings:
    $key_5280 = { 01 ef [2] 25 e1 [2] 0e cd [2] 20 ef [2] 34 f4 [2] 3b ee [2] 25 f3 [2] 27 f2 [2] 3c f4 [2] 20 f3 [2] 3c dc }

  condition:
    any of them
}