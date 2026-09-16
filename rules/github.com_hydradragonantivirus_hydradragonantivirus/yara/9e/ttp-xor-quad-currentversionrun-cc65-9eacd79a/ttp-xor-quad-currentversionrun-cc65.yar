rule TTP_XOR_QUAD_CurrentVersionRun_cc65 {
  strings:
    $key_cc65 = { 9f 0a [2] bb 04 [2] 90 28 [2] be 0a [2] aa 11 [2] a5 0b [2] bb 16 [2] b9 17 [2] a2 11 [2] be 16 [2] a2 39 }

  condition:
    any of them
}