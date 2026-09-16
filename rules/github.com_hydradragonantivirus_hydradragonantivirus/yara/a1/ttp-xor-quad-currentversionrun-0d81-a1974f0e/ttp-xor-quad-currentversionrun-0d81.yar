rule TTP_XOR_QUAD_CurrentVersionRun_0d81 {
  strings:
    $key_0d81 = { 5e ee [2] 7a e0 [2] 51 cc [2] 7f ee [2] 6b f5 [2] 64 ef [2] 7a f2 [2] 78 f3 [2] 63 f5 [2] 7f f2 [2] 63 dd }

  condition:
    any of them
}