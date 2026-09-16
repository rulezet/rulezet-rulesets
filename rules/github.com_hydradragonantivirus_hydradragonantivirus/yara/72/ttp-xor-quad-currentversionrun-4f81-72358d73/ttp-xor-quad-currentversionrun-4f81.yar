rule TTP_XOR_QUAD_CurrentVersionRun_4f81 {
  strings:
    $key_4f81 = { 1c ee [2] 38 e0 [2] 13 cc [2] 3d ee [2] 29 f5 [2] 26 ef [2] 38 f2 [2] 3a f3 [2] 21 f5 [2] 3d f2 [2] 21 dd }

  condition:
    any of them
}