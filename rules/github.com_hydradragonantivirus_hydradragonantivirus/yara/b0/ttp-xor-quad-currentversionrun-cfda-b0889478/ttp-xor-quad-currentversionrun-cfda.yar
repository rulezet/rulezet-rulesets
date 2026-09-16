rule TTP_XOR_QUAD_CurrentVersionRun_cfda {
  strings:
    $key_cfda = { 9c b5 [2] b8 bb [2] 93 97 [2] bd b5 [2] a9 ae [2] a6 b4 [2] b8 a9 [2] ba a8 [2] a1 ae [2] bd a9 [2] a1 86 }

  condition:
    any of them
}