rule TTP_XOR_QUAD_CurrentVersionRun_cad8 {
  strings:
    $key_cad8 = { 99 b7 [2] bd b9 [2] 96 95 [2] b8 b7 [2] ac ac [2] a3 b6 [2] bd ab [2] bf aa [2] a4 ac [2] b8 ab [2] a4 84 }

  condition:
    any of them
}