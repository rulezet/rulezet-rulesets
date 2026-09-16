rule TTP_XOR_QUAD_CurrentVersionRun_29b3 {
  strings:
    $key_29b3 = { 7a dc [2] 5e d2 [2] 75 fe [2] 5b dc [2] 4f c7 [2] 40 dd [2] 5e c0 [2] 5c c1 [2] 47 c7 [2] 5b c0 [2] 47 ef }

  condition:
    any of them
}