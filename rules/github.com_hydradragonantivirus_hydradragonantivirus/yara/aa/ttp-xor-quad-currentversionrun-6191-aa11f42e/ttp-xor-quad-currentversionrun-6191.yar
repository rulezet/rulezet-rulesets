rule TTP_XOR_QUAD_CurrentVersionRun_6191 {
  strings:
    $key_6191 = { 32 fe [2] 16 f0 [2] 3d dc [2] 13 fe [2] 07 e5 [2] 08 ff [2] 16 e2 [2] 14 e3 [2] 0f e5 [2] 13 e2 [2] 0f cd }

  condition:
    any of them
}