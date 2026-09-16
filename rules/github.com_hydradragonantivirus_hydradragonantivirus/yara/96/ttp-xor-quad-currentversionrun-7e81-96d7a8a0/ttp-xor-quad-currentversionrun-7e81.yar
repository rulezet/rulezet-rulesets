rule TTP_XOR_QUAD_CurrentVersionRun_7e81 {
  strings:
    $key_7e81 = { 2d ee [2] 09 e0 [2] 22 cc [2] 0c ee [2] 18 f5 [2] 17 ef [2] 09 f2 [2] 0b f3 [2] 10 f5 [2] 0c f2 [2] 10 dd }

  condition:
    any of them
}