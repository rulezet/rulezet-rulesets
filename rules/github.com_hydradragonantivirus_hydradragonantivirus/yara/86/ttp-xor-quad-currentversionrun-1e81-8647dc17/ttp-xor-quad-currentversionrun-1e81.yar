rule TTP_XOR_QUAD_CurrentVersionRun_1e81 {
  strings:
    $key_1e81 = { 4d ee [2] 69 e0 [2] 42 cc [2] 6c ee [2] 78 f5 [2] 77 ef [2] 69 f2 [2] 6b f3 [2] 70 f5 [2] 6c f2 [2] 70 dd }

  condition:
    any of them
}