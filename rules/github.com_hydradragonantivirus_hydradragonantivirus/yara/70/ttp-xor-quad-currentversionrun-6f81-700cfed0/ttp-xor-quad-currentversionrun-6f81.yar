rule TTP_XOR_QUAD_CurrentVersionRun_6f81 {
  strings:
    $key_6f81 = { 3c ee [2] 18 e0 [2] 33 cc [2] 1d ee [2] 09 f5 [2] 06 ef [2] 18 f2 [2] 1a f3 [2] 01 f5 [2] 1d f2 [2] 01 dd }

  condition:
    any of them
}