rule TTP_XOR_QUAD_CurrentVersionRun_cce5 {
  strings:
    $key_cce5 = { 9f 8a [2] bb 84 [2] 90 a8 [2] be 8a [2] aa 91 [2] a5 8b [2] bb 96 [2] b9 97 [2] a2 91 [2] be 96 [2] a2 b9 }

  condition:
    any of them
}