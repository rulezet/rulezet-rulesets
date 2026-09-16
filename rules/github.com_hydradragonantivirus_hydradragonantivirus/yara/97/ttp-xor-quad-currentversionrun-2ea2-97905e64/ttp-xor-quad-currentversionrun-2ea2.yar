rule TTP_XOR_QUAD_CurrentVersionRun_2ea2 {
  strings:
    $key_2ea2 = { 7d cd [2] 59 c3 [2] 72 ef [2] 5c cd [2] 48 d6 [2] 47 cc [2] 59 d1 [2] 5b d0 [2] 40 d6 [2] 5c d1 [2] 40 fe }

  condition:
    any of them
}