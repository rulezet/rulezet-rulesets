rule TTP_XOR_QUAD_CurrentVersionRun_cad6 {
  strings:
    $key_cad6 = { 99 b9 [2] bd b7 [2] 96 9b [2] b8 b9 [2] ac a2 [2] a3 b8 [2] bd a5 [2] bf a4 [2] a4 a2 [2] b8 a5 [2] a4 8a }

  condition:
    any of them
}