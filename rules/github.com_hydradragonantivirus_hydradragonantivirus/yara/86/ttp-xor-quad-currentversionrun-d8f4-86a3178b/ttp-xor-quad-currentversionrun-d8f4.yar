rule TTP_XOR_QUAD_CurrentVersionRun_d8f4 {
  strings:
    $key_d8f4 = { 8b 9b [2] af 95 [2] 84 b9 [2] aa 9b [2] be 80 [2] b1 9a [2] af 87 [2] ad 86 [2] b6 80 [2] aa 87 [2] b6 a8 }

  condition:
    any of them
}