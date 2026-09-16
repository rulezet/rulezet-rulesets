rule TTP_XOR_QUAD_CurrentVersionRun_c0d9 {
  strings:
    $key_c0d9 = { 93 b6 [2] b7 b8 [2] 9c 94 [2] b2 b6 [2] a6 ad [2] a9 b7 [2] b7 aa [2] b5 ab [2] ae ad [2] b2 aa [2] ae 85 }

  condition:
    any of them
}