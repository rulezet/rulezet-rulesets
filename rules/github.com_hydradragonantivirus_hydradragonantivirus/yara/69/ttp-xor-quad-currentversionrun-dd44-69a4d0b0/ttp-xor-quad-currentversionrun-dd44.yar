rule TTP_XOR_QUAD_CurrentVersionRun_dd44 {
  strings:
    $key_dd44 = { 8e 2b [2] aa 25 [2] 81 09 [2] af 2b [2] bb 30 [2] b4 2a [2] aa 37 [2] a8 36 [2] b3 30 [2] af 37 [2] b3 18 }

  condition:
    any of them
}