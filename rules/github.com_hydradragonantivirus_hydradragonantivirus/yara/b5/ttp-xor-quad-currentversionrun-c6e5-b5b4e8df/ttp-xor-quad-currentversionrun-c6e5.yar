rule TTP_XOR_QUAD_CurrentVersionRun_c6e5 {
  strings:
    $key_c6e5 = { 95 8a [2] b1 84 [2] 9a a8 [2] b4 8a [2] a0 91 [2] af 8b [2] b1 96 [2] b3 97 [2] a8 91 [2] b4 96 [2] a8 b9 }

  condition:
    any of them
}