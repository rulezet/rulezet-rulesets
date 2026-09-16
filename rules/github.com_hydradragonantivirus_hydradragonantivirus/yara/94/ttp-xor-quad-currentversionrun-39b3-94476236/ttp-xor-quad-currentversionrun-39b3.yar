rule TTP_XOR_QUAD_CurrentVersionRun_39b3 {
  strings:
    $key_39b3 = { 6a dc [2] 4e d2 [2] 65 fe [2] 4b dc [2] 5f c7 [2] 50 dd [2] 4e c0 [2] 4c c1 [2] 57 c7 [2] 4b c0 [2] 57 ef }

  condition:
    any of them
}