rule TTP_XOR_QUAD_CurrentVersionRun_dd47 {
  strings:
    $key_dd47 = { 8e 28 [2] aa 26 [2] 81 0a [2] af 28 [2] bb 33 [2] b4 29 [2] aa 34 [2] a8 35 [2] b3 33 [2] af 34 [2] b3 1b }

  condition:
    any of them
}