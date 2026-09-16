rule TTP_XOR_QUAD_CurrentVersionRun_dd54 {
  strings:
    $key_dd54 = { 8e 3b [2] aa 35 [2] 81 19 [2] af 3b [2] bb 20 [2] b4 3a [2] aa 27 [2] a8 26 [2] b3 20 [2] af 27 [2] b3 08 }

  condition:
    any of them
}