rule TTP_XOR_QUAD_CurrentVersionRun_7280 {
  strings:
    $key_7280 = { 21 ef [2] 05 e1 [2] 2e cd [2] 00 ef [2] 14 f4 [2] 1b ee [2] 05 f3 [2] 07 f2 [2] 1c f4 [2] 00 f3 [2] 1c dc }

  condition:
    any of them
}