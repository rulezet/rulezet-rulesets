rule TTP_XOR_QUAD_CurrentVersionRun_d8e8 {
  strings:
    $key_d8e8 = { 8b 87 [2] af 89 [2] 84 a5 [2] aa 87 [2] be 9c [2] b1 86 [2] af 9b [2] ad 9a [2] b6 9c [2] aa 9b [2] b6 b4 }

  condition:
    any of them
}