rule TTP_XOR_QUAD_CurrentVersionRun_1bb3 {
  strings:
    $key_1bb3 = { 48 dc [2] 6c d2 [2] 47 fe [2] 69 dc [2] 7d c7 [2] 72 dd [2] 6c c0 [2] 6e c1 [2] 75 c7 [2] 69 c0 [2] 75 ef }

  condition:
    any of them
}