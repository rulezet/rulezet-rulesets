rule TTP_XOR_QUAD_CurrentVersionRun_4bb3 {
  strings:
    $key_4bb3 = { 18 dc [2] 3c d2 [2] 17 fe [2] 39 dc [2] 2d c7 [2] 22 dd [2] 3c c0 [2] 3e c1 [2] 25 c7 [2] 39 c0 [2] 25 ef }

  condition:
    any of them
}