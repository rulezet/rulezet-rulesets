rule TTP_XOR_QUAD_CurrentVersionRun_dd78 {
  strings:
    $key_dd78 = { 8e 17 [2] aa 19 [2] 81 35 [2] af 17 [2] bb 0c [2] b4 16 [2] aa 0b [2] a8 0a [2] b3 0c [2] af 0b [2] b3 24 }

  condition:
    any of them
}