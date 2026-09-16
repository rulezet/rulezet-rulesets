rule TTP_XOR_QUAD_CurrentVersionRun_d380 {
  strings:
    $key_d380 = { 80 ef [2] a4 e1 [2] 8f cd [2] a1 ef [2] b5 f4 [2] ba ee [2] a4 f3 [2] a6 f2 [2] bd f4 [2] a1 f3 [2] bd dc }

  condition:
    any of them
}