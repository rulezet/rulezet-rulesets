rule TTP_XOR_QUAD_CurrentVersionRun_7981 {
  strings:
    $key_7981 = { 2a ee [2] 0e e0 [2] 25 cc [2] 0b ee [2] 1f f5 [2] 10 ef [2] 0e f2 [2] 0c f3 [2] 17 f5 [2] 0b f2 [2] 17 dd }

  condition:
    any of them
}