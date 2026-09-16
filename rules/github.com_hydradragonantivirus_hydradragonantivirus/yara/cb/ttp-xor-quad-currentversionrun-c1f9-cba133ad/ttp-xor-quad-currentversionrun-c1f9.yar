rule TTP_XOR_QUAD_CurrentVersionRun_c1f9 {
  strings:
    $key_c1f9 = { 92 96 [2] b6 98 [2] 9d b4 [2] b3 96 [2] a7 8d [2] a8 97 [2] b6 8a [2] b4 8b [2] af 8d [2] b3 8a [2] af a5 }

  condition:
    any of them
}