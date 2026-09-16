rule TTP_XOR_QUAD_CurrentVersionRun_c157 {
  strings:
    $key_c157 = { 92 38 [2] b6 36 [2] 9d 1a [2] b3 38 [2] a7 23 [2] a8 39 [2] b6 24 [2] b4 25 [2] af 23 [2] b3 24 [2] af 0b }

  condition:
    any of them
}