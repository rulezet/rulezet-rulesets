rule TTP_XOR_QUAD_CurrentVersionRun_3280 {
  strings:
    $key_3280 = { 61 ef [2] 45 e1 [2] 6e cd [2] 40 ef [2] 54 f4 [2] 5b ee [2] 45 f3 [2] 47 f2 [2] 5c f4 [2] 40 f3 [2] 5c dc }

  condition:
    any of them
}