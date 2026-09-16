rule TTP_XOR_QUAD_CurrentVersionRun_4ea2 {
  strings:
    $key_4ea2 = { 1d cd [2] 39 c3 [2] 12 ef [2] 3c cd [2] 28 d6 [2] 27 cc [2] 39 d1 [2] 3b d0 [2] 20 d6 [2] 3c d1 [2] 20 fe }

  condition:
    any of them
}