rule TTP_XOR_QUAD_CurrentVersionRun_1d81 {
  strings:
    $key_1d81 = { 4e ee [2] 6a e0 [2] 41 cc [2] 6f ee [2] 7b f5 [2] 74 ef [2] 6a f2 [2] 68 f3 [2] 73 f5 [2] 6f f2 [2] 73 dd }

  condition:
    any of them
}