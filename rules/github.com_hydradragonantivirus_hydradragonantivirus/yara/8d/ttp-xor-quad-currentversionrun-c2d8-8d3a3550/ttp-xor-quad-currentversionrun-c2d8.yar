rule TTP_XOR_QUAD_CurrentVersionRun_c2d8 {
  strings:
    $key_c2d8 = { 91 b7 [2] b5 b9 [2] 9e 95 [2] b0 b7 [2] a4 ac [2] ab b6 [2] b5 ab [2] b7 aa [2] ac ac [2] b0 ab [2] ac 84 }

  condition:
    any of them
}