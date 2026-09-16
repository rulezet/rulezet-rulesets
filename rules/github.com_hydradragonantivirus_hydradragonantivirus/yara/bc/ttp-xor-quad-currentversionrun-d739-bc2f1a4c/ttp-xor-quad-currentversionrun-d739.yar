rule TTP_XOR_QUAD_CurrentVersionRun_d739 {
  strings:
    $key_d739 = { 84 56 [2] a0 58 [2] 8b 74 [2] a5 56 [2] b1 4d [2] be 57 [2] a0 4a [2] a2 4b [2] b9 4d [2] a5 4a [2] b9 65 }

  condition:
    any of them
}