rule TTP_XOR_QUAD_CurrentVersionRun_d765 {
  strings:
    $key_d765 = { 84 0a [2] a0 04 [2] 8b 28 [2] a5 0a [2] b1 11 [2] be 0b [2] a0 16 [2] a2 17 [2] b9 11 [2] a5 16 [2] b9 39 }

  condition:
    any of them
}