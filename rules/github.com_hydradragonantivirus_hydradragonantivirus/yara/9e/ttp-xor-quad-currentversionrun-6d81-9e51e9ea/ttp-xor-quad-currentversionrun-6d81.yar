rule TTP_XOR_QUAD_CurrentVersionRun_6d81 {
  strings:
    $key_6d81 = { 3e ee [2] 1a e0 [2] 31 cc [2] 1f ee [2] 0b f5 [2] 04 ef [2] 1a f2 [2] 18 f3 [2] 03 f5 [2] 1f f2 [2] 03 dd }

  condition:
    any of them
}