rule TTP_XOR_QUAD_CurrentVersionRun_c608 {
  strings:
    $key_c608 = { 95 67 [2] b1 69 [2] 9a 45 [2] b4 67 [2] a0 7c [2] af 66 [2] b1 7b [2] b3 7a [2] a8 7c [2] b4 7b [2] a8 54 }

  condition:
    any of them
}