rule TTP_XOR_QUAD_CurrentVersionRun_3bb3 {
  strings:
    $key_3bb3 = { 68 dc [2] 4c d2 [2] 67 fe [2] 49 dc [2] 5d c7 [2] 52 dd [2] 4c c0 [2] 4e c1 [2] 55 c7 [2] 49 c0 [2] 55 ef }

  condition:
    any of them
}