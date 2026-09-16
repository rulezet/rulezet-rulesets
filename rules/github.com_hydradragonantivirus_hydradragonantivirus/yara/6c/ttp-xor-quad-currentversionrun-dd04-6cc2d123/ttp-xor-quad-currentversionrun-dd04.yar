rule TTP_XOR_QUAD_CurrentVersionRun_dd04 {
  strings:
    $key_dd04 = { 8e 6b [2] aa 65 [2] 81 49 [2] af 6b [2] bb 70 [2] b4 6a [2] aa 77 [2] a8 76 [2] b3 70 [2] af 77 [2] b3 58 }

  condition:
    any of them
}