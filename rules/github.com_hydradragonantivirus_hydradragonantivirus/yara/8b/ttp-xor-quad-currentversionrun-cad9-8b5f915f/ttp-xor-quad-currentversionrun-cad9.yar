rule TTP_XOR_QUAD_CurrentVersionRun_cad9 {
  strings:
    $key_cad9 = { 99 b6 [2] bd b8 [2] 96 94 [2] b8 b6 [2] ac ad [2] a3 b7 [2] bd aa [2] bf ab [2] a4 ad [2] b8 aa [2] a4 85 }

  condition:
    any of them
}