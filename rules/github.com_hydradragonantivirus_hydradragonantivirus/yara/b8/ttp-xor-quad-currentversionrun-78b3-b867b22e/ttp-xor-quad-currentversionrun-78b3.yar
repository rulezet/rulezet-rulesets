rule TTP_XOR_QUAD_CurrentVersionRun_78b3 {
  strings:
    $key_78b3 = { 2b dc [2] 0f d2 [2] 24 fe [2] 0a dc [2] 1e c7 [2] 11 dd [2] 0f c0 [2] 0d c1 [2] 16 c7 [2] 0a c0 [2] 16 ef }

  condition:
    any of them
}