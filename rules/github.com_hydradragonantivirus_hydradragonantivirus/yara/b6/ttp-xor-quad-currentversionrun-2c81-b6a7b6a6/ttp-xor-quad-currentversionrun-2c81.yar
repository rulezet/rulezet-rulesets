rule TTP_XOR_QUAD_CurrentVersionRun_2c81 {
  strings:
    $key_2c81 = { 7f ee [2] 5b e0 [2] 70 cc [2] 5e ee [2] 4a f5 [2] 45 ef [2] 5b f2 [2] 59 f3 [2] 42 f5 [2] 5e f2 [2] 42 dd }

  condition:
    any of them
}