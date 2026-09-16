rule TTP_XOR_QUAD_CurrentVersionRun_5c81 {
  strings:
    $key_5c81 = { 0f ee [2] 2b e0 [2] 00 cc [2] 2e ee [2] 3a f5 [2] 35 ef [2] 2b f2 [2] 29 f3 [2] 32 f5 [2] 2e f2 [2] 32 dd }

  condition:
    any of them
}