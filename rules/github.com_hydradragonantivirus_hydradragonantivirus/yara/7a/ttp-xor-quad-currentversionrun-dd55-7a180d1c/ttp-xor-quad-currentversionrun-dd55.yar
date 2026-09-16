rule TTP_XOR_QUAD_CurrentVersionRun_dd55 {
  strings:
    $key_dd55 = { 8e 3a [2] aa 34 [2] 81 18 [2] af 3a [2] bb 21 [2] b4 3b [2] aa 26 [2] a8 27 [2] b3 21 [2] af 26 [2] b3 09 }

  condition:
    any of them
}