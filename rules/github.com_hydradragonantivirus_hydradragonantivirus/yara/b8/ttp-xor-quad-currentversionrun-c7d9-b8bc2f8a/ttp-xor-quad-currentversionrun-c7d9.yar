rule TTP_XOR_QUAD_CurrentVersionRun_c7d9 {
  strings:
    $key_c7d9 = { 94 b6 [2] b0 b8 [2] 9b 94 [2] b5 b6 [2] a1 ad [2] ae b7 [2] b0 aa [2] b2 ab [2] a9 ad [2] b5 aa [2] a9 85 }

  condition:
    any of them
}