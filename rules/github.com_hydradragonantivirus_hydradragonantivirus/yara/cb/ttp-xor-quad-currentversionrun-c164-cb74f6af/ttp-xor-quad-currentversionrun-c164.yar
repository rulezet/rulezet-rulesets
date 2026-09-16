rule TTP_XOR_QUAD_CurrentVersionRun_c164 {
  strings:
    $key_c164 = { 92 0b [2] b6 05 [2] 9d 29 [2] b3 0b [2] a7 10 [2] a8 0a [2] b6 17 [2] b4 16 [2] af 10 [2] b3 17 [2] af 38 }

  condition:
    any of them
}