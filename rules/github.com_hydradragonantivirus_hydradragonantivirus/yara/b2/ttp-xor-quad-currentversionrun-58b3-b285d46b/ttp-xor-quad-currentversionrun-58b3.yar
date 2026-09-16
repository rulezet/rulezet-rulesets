rule TTP_XOR_QUAD_CurrentVersionRun_58b3 {
  strings:
    $key_58b3 = { 0b dc [2] 2f d2 [2] 04 fe [2] 2a dc [2] 3e c7 [2] 31 dd [2] 2f c0 [2] 2d c1 [2] 36 c7 [2] 2a c0 [2] 36 ef }

  condition:
    any of them
}