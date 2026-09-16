rule TTP_XOR_QUAD_CurrentVersionRun_6bb3 {
  strings:
    $key_6bb3 = { 38 dc [2] 1c d2 [2] 37 fe [2] 19 dc [2] 0d c7 [2] 02 dd [2] 1c c0 [2] 1e c1 [2] 05 c7 [2] 19 c0 [2] 05 ef }

  condition:
    any of them
}