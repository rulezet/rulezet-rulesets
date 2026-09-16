rule TTP_XOR_QUAD_CurrentVersionRun_d7f9 {
  strings:
    $key_d7f9 = { 84 96 [2] a0 98 [2] 8b b4 [2] a5 96 [2] b1 8d [2] be 97 [2] a0 8a [2] a2 8b [2] b9 8d [2] a5 8a [2] b9 a5 }

  condition:
    any of them
}