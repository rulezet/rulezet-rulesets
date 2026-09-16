rule TTP_XOR_QUAD_CurrentVersionRun_c154 {
  strings:
    $key_c154 = { 92 3b [2] b6 35 [2] 9d 19 [2] b3 3b [2] a7 20 [2] a8 3a [2] b6 27 [2] b4 26 [2] af 20 [2] b3 27 [2] af 08 }

  condition:
    any of them
}