rule TTP_XOR_QUAD_CurrentVersionRun_d715 {
  strings:
    $key_d715 = { 84 7a [2] a0 74 [2] 8b 58 [2] a5 7a [2] b1 61 [2] be 7b [2] a0 66 [2] a2 67 [2] b9 61 [2] a5 66 [2] b9 49 }

  condition:
    any of them
}