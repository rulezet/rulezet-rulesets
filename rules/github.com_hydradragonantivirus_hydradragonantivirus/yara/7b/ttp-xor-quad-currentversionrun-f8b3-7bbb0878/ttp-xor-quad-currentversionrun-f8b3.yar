rule TTP_XOR_QUAD_CurrentVersionRun_f8b3 {
  strings:
    $key_f8b3 = { ab dc [2] 8f d2 [2] a4 fe [2] 8a dc [2] 9e c7 [2] 91 dd [2] 8f c0 [2] 8d c1 [2] 96 c7 [2] 8a c0 [2] 96 ef }

  condition:
    any of them
}