rule TTP_XOR_QUAD_CurrentVersionRun_d4d9 {
  strings:
    $key_d4d9 = { 87 b6 [2] a3 b8 [2] 88 94 [2] a6 b6 [2] b2 ad [2] bd b7 [2] a3 aa [2] a1 ab [2] ba ad [2] a6 aa [2] ba 85 }

  condition:
    any of them
}