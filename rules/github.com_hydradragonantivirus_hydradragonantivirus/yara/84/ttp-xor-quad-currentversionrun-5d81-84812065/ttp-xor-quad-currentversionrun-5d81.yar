rule TTP_XOR_QUAD_CurrentVersionRun_5d81 {
  strings:
    $key_5d81 = { 0e ee [2] 2a e0 [2] 01 cc [2] 2f ee [2] 3b f5 [2] 34 ef [2] 2a f2 [2] 28 f3 [2] 33 f5 [2] 2f f2 [2] 33 dd }

  condition:
    any of them
}