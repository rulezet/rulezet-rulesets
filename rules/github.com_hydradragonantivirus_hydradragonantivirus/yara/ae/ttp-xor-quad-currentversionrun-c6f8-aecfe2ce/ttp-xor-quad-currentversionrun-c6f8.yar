rule TTP_XOR_QUAD_CurrentVersionRun_c6f8 {
  strings:
    $key_c6f8 = { 95 97 [2] b1 99 [2] 9a b5 [2] b4 97 [2] a0 8c [2] af 96 [2] b1 8b [2] b3 8a [2] a8 8c [2] b4 8b [2] a8 a4 }

  condition:
    any of them
}