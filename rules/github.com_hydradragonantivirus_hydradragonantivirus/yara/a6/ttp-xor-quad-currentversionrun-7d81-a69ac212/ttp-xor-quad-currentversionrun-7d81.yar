rule TTP_XOR_QUAD_CurrentVersionRun_7d81 {
  strings:
    $key_7d81 = { 2e ee [2] 0a e0 [2] 21 cc [2] 0f ee [2] 1b f5 [2] 14 ef [2] 0a f2 [2] 08 f3 [2] 13 f5 [2] 0f f2 [2] 13 dd }

  condition:
    any of them
}