rule TTP_XOR_QUAD_CurrentVersionRun_d7e9 {
  strings:
    $key_d7e9 = { 84 86 [2] a0 88 [2] 8b a4 [2] a5 86 [2] b1 9d [2] be 87 [2] a0 9a [2] a2 9b [2] b9 9d [2] a5 9a [2] b9 b5 }

  condition:
    any of them
}