rule TTP_XOR_QUAD_CurrentVersionRun_79b3 {
  strings:
    $key_79b3 = { 2a dc [2] 0e d2 [2] 25 fe [2] 0b dc [2] 1f c7 [2] 10 dd [2] 0e c0 [2] 0c c1 [2] 17 c7 [2] 0b c0 [2] 17 ef }

  condition:
    any of them
}