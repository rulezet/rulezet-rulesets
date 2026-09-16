rule TTP_XOR_QUAD_CurrentVersionRun_c1f8 {
  strings:
    $key_c1f8 = { 92 97 [2] b6 99 [2] 9d b5 [2] b3 97 [2] a7 8c [2] a8 96 [2] b6 8b [2] b4 8a [2] af 8c [2] b3 8b [2] af a4 }

  condition:
    any of them
}