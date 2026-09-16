rule TTP_XOR_QUAD_CurrentVersionRun_d724 {
  strings:
    $key_d724 = { 84 4b [2] a0 45 [2] 8b 69 [2] a5 4b [2] b1 50 [2] be 4a [2] a0 57 [2] a2 56 [2] b9 50 [2] a5 57 [2] b9 78 }

  condition:
    any of them
}