rule TTP_XOR_QUAD_CurrentVersionRun_e280 {
  strings:
    $key_e280 = { b1 ef [2] 95 e1 [2] be cd [2] 90 ef [2] 84 f4 [2] 8b ee [2] 95 f3 [2] 97 f2 [2] 8c f4 [2] 90 f3 [2] 8c dc }

  condition:
    any of them
}