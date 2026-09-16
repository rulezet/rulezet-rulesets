rule TTP_XOR_QUAD_CurrentVersionRun_d7f8 {
  strings:
    $key_d7f8 = { 84 97 [2] a0 99 [2] 8b b5 [2] a5 97 [2] b1 8c [2] be 96 [2] a0 8b [2] a2 8a [2] b9 8c [2] a5 8b [2] b9 a4 }

  condition:
    any of them
}