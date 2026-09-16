rule TTP_XOR_QUAD_CurrentVersionRun_5e81 {
  strings:
    $key_5e81 = { 0d ee [2] 29 e0 [2] 02 cc [2] 2c ee [2] 38 f5 [2] 37 ef [2] 29 f2 [2] 2b f3 [2] 30 f5 [2] 2c f2 [2] 30 dd }

  condition:
    any of them
}