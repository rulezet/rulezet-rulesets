rule TTP_XOR_QUAD_CurrentVersionRun_c119 {
  strings:
    $key_c119 = { 92 76 [2] b6 78 [2] 9d 54 [2] b3 76 [2] a7 6d [2] a8 77 [2] b6 6a [2] b4 6b [2] af 6d [2] b3 6a [2] af 45 }

  condition:
    any of them
}