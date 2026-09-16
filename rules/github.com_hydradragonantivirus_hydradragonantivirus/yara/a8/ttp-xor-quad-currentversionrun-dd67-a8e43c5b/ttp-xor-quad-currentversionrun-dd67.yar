rule TTP_XOR_QUAD_CurrentVersionRun_dd67 {
  strings:
    $key_dd67 = { 8e 08 [2] aa 06 [2] 81 2a [2] af 08 [2] bb 13 [2] b4 09 [2] aa 14 [2] a8 15 [2] b3 13 [2] af 14 [2] b3 3b }

  condition:
    any of them
}