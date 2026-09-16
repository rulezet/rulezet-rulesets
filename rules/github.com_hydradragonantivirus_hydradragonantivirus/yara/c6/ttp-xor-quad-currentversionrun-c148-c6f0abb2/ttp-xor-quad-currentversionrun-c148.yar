rule TTP_XOR_QUAD_CurrentVersionRun_c148 {
  strings:
    $key_c148 = { 92 27 [2] b6 29 [2] 9d 05 [2] b3 27 [2] a7 3c [2] a8 26 [2] b6 3b [2] b4 3a [2] af 3c [2] b3 3b [2] af 14 }

  condition:
    any of them
}