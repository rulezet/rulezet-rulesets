rule TTP_XOR_QUAD_CurrentVersionRun_f9a2 {
  strings:
    $key_f9a2 = { aa cd [2] 8e c3 [2] a5 ef [2] 8b cd [2] 9f d6 [2] 90 cc [2] 8e d1 [2] 8c d0 [2] 97 d6 [2] 8b d1 [2] 97 fe }

  condition:
    any of them
}