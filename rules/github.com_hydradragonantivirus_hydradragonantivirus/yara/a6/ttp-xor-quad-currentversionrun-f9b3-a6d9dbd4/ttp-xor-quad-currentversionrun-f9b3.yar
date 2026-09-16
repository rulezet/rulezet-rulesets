rule TTP_XOR_QUAD_CurrentVersionRun_f9b3 {
  strings:
    $key_f9b3 = { aa dc [2] 8e d2 [2] a5 fe [2] 8b dc [2] 9f c7 [2] 90 dd [2] 8e c0 [2] 8c c1 [2] 97 c7 [2] 8b c0 [2] 97 ef }

  condition:
    any of them
}