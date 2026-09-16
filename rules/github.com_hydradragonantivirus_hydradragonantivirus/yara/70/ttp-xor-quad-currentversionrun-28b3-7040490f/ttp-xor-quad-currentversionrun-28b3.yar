rule TTP_XOR_QUAD_CurrentVersionRun_28b3 {
  strings:
    $key_28b3 = { 7b dc [2] 5f d2 [2] 74 fe [2] 5a dc [2] 4e c7 [2] 41 dd [2] 5f c0 [2] 5d c1 [2] 46 c7 [2] 5a c0 [2] 46 ef }

  condition:
    any of them
}