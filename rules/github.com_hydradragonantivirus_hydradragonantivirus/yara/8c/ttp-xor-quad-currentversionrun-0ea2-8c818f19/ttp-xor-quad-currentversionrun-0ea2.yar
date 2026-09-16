rule TTP_XOR_QUAD_CurrentVersionRun_0ea2 {
  strings:
    $key_0ea2 = { 5d cd [2] 79 c3 [2] 52 ef [2] 7c cd [2] 68 d6 [2] 67 cc [2] 79 d1 [2] 7b d0 [2] 60 d6 [2] 7c d1 [2] 60 fe }

  condition:
    any of them
}