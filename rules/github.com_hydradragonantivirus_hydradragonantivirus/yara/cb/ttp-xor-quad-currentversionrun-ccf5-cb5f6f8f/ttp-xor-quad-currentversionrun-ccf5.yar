rule TTP_XOR_QUAD_CurrentVersionRun_ccf5 {
  strings:
    $key_ccf5 = { 9f 9a [2] bb 94 [2] 90 b8 [2] be 9a [2] aa 81 [2] a5 9b [2] bb 86 [2] b9 87 [2] a2 81 [2] be 86 [2] a2 a9 }

  condition:
    any of them
}