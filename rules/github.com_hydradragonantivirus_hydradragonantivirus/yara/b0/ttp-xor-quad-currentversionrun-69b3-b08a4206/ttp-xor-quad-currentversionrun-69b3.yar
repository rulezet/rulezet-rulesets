rule TTP_XOR_QUAD_CurrentVersionRun_69b3 {
  strings:
    $key_69b3 = { 3a dc [2] 1e d2 [2] 35 fe [2] 1b dc [2] 0f c7 [2] 00 dd [2] 1e c0 [2] 1c c1 [2] 07 c7 [2] 1b c0 [2] 07 ef }

  condition:
    any of them
}