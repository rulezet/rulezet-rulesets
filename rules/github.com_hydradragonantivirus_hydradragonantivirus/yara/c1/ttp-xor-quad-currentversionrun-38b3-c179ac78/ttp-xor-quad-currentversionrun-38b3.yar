rule TTP_XOR_QUAD_CurrentVersionRun_38b3 {
  strings:
    $key_38b3 = { 6b dc [2] 4f d2 [2] 64 fe [2] 4a dc [2] 5e c7 [2] 51 dd [2] 4f c0 [2] 4d c1 [2] 56 c7 [2] 4a c0 [2] 56 ef }

  condition:
    any of them
}