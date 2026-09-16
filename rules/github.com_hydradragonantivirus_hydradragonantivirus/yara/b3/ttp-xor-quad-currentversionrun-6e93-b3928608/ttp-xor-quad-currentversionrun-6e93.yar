rule TTP_XOR_QUAD_CurrentVersionRun_6e93 {
  strings:
    $key_6e93 = { 3d fc [2] 19 f2 [2] 32 de [2] 1c fc [2] 08 e7 [2] 07 fd [2] 19 e0 [2] 1b e1 [2] 00 e7 [2] 1c e0 [2] 00 cf }

  condition:
    any of them
}