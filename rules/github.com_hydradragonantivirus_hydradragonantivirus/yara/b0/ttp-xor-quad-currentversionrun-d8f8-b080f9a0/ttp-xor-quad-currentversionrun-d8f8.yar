rule TTP_XOR_QUAD_CurrentVersionRun_d8f8 {
  strings:
    $key_d8f8 = { 8b 97 [2] af 99 [2] 84 b5 [2] aa 97 [2] be 8c [2] b1 96 [2] af 8b [2] ad 8a [2] b6 8c [2] aa 8b [2] b6 a4 }

  condition:
    any of them
}