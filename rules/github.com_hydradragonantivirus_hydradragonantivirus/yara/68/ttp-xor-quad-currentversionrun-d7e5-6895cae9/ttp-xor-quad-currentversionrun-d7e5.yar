rule TTP_XOR_QUAD_CurrentVersionRun_d7e5 {
  strings:
    $key_d7e5 = { 84 8a [2] a0 84 [2] 8b a8 [2] a5 8a [2] b1 91 [2] be 8b [2] a0 96 [2] a2 97 [2] b9 91 [2] a5 96 [2] b9 b9 }

  condition:
    any of them
}