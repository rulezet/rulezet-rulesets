rule TTP_XOR_QUAD_CurrentVersionRun_d1d9 {
  strings:
    $key_d1d9 = { 82 b6 [2] a6 b8 [2] 8d 94 [2] a3 b6 [2] b7 ad [2] b8 b7 [2] a6 aa [2] a4 ab [2] bf ad [2] a3 aa [2] bf 85 }

  condition:
    any of them
}