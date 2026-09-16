rule TTP_XOR_QUAD_CurrentVersionRun_d8e4 {
  strings:
    $key_d8e4 = { 8b 8b [2] af 85 [2] 84 a9 [2] aa 8b [2] be 90 [2] b1 8a [2] af 97 [2] ad 96 [2] b6 90 [2] aa 97 [2] b6 b8 }

  condition:
    any of them
}