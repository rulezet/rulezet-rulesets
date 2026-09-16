rule TTP_XOR_QUAD_CurrentVersionRun_d745 {
  strings:
    $key_d745 = { 84 2a [2] a0 24 [2] 8b 08 [2] a5 2a [2] b1 31 [2] be 2b [2] a0 36 [2] a2 37 [2] b9 31 [2] a5 36 [2] b9 19 }

  condition:
    any of them
}