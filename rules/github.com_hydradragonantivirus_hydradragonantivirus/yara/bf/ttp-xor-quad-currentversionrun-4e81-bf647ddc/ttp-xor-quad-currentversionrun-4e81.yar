rule TTP_XOR_QUAD_CurrentVersionRun_4e81 {
  strings:
    $key_4e81 = { 1d ee [2] 39 e0 [2] 12 cc [2] 3c ee [2] 28 f5 [2] 27 ef [2] 39 f2 [2] 3b f3 [2] 20 f5 [2] 3c f2 [2] 20 dd }

  condition:
    any of them
}