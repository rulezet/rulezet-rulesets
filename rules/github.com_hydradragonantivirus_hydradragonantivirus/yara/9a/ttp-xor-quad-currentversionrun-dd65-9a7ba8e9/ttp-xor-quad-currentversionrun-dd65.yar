rule TTP_XOR_QUAD_CurrentVersionRun_dd65 {
  strings:
    $key_dd65 = { 8e 0a [2] aa 04 [2] 81 28 [2] af 0a [2] bb 11 [2] b4 0b [2] aa 16 [2] a8 17 [2] b3 11 [2] af 16 [2] b3 39 }

  condition:
    any of them
}