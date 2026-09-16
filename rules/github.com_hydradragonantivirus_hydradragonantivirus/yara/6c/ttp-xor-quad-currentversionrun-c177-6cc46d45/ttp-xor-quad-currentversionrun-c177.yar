rule TTP_XOR_QUAD_CurrentVersionRun_c177 {
  strings:
    $key_c177 = { 92 18 [2] b6 16 [2] 9d 3a [2] b3 18 [2] a7 03 [2] a8 19 [2] b6 04 [2] b4 05 [2] af 03 [2] b3 04 [2] af 2b }

  condition:
    any of them
}