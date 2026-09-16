rule TTP_XOR_QUAD_CurrentVersionRun_cfd8 {
  strings:
    $key_cfd8 = { 9c b7 [2] b8 b9 [2] 93 95 [2] bd b7 [2] a9 ac [2] a6 b6 [2] b8 ab [2] ba aa [2] a1 ac [2] bd ab [2] a1 84 }

  condition:
    any of them
}