rule TTP_XOR_QUAD_CurrentVersionRun_c777 {
  strings:
    $key_c777 = { 94 18 [2] b0 16 [2] 9b 3a [2] b5 18 [2] a1 03 [2] ae 19 [2] b0 04 [2] b2 05 [2] a9 03 [2] b5 04 [2] a9 2b }

  condition:
    any of them
}