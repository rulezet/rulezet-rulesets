rule TTP_XOR_QUAD_CurrentVersionRun_5ea2 {
  strings:
    $key_5ea2 = { 0d cd [2] 29 c3 [2] 02 ef [2] 2c cd [2] 38 d6 [2] 37 cc [2] 29 d1 [2] 2b d0 [2] 30 d6 [2] 2c d1 [2] 30 fe }

  condition:
    any of them
}