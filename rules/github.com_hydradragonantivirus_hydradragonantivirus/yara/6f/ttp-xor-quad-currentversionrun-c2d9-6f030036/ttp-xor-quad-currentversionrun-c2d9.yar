rule TTP_XOR_QUAD_CurrentVersionRun_c2d9 {
  strings:
    $key_c2d9 = { 91 b6 [2] b5 b8 [2] 9e 94 [2] b0 b6 [2] a4 ad [2] ab b7 [2] b5 aa [2] b7 ab [2] ac ad [2] b0 aa [2] ac 85 }

  condition:
    any of them
}