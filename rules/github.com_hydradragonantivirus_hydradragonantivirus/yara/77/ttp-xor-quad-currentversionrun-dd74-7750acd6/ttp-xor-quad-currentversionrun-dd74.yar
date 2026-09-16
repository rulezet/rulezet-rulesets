rule TTP_XOR_QUAD_CurrentVersionRun_dd74 {
  strings:
    $key_dd74 = { 8e 1b [2] aa 15 [2] 81 39 [2] af 1b [2] bb 00 [2] b4 1a [2] aa 07 [2] a8 06 [2] b3 00 [2] af 07 [2] b3 28 }

  condition:
    any of them
}