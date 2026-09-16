rule TTP_XOR_QUAD_CurrentVersionRun_3ea2 {
  strings:
    $key_3ea2 = { 6d cd [2] 49 c3 [2] 62 ef [2] 4c cd [2] 58 d6 [2] 57 cc [2] 49 d1 [2] 4b d0 [2] 50 d6 [2] 4c d1 [2] 50 fe }

  condition:
    any of them
}