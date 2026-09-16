rule TTP_XOR_QUAD_CurrentVersionRun_dd64 {
  strings:
    $key_dd64 = { 8e 0b [2] aa 05 [2] 81 29 [2] af 0b [2] bb 10 [2] b4 0a [2] aa 17 [2] a8 16 [2] b3 10 [2] af 17 [2] b3 38 }

  condition:
    any of them
}