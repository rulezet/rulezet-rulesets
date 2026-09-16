rule TTP_XOR_QUAD_CurrentVersionRun_c109 {
  strings:
    $key_c109 = { 92 66 [2] b6 68 [2] 9d 44 [2] b3 66 [2] a7 7d [2] a8 67 [2] b6 7a [2] b4 7b [2] af 7d [2] b3 7a [2] af 55 }

  condition:
    any of them
}