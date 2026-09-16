rule TTP_XOR_QUAD_CurrentVersionRun_6e81 {
  strings:
    $key_6e81 = { 3d ee [2] 19 e0 [2] 32 cc [2] 1c ee [2] 08 f5 [2] 07 ef [2] 19 f2 [2] 1b f3 [2] 00 f5 [2] 1c f2 [2] 00 dd }

  condition:
    any of them
}