rule TTP_XOR_QUAD_CurrentVersionRun_0bb3 {
  strings:
    $key_0bb3 = { 58 dc [2] 7c d2 [2] 57 fe [2] 79 dc [2] 6d c7 [2] 62 dd [2] 7c c0 [2] 7e c1 [2] 65 c7 [2] 79 c0 [2] 65 ef }

  condition:
    any of them
}