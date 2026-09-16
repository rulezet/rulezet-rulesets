rule TTP_XOR_QUAD_CurrentVersionRun_d8e5 {
  strings:
    $key_d8e5 = { 8b 8a [2] af 84 [2] 84 a8 [2] aa 8a [2] be 91 [2] b1 8b [2] af 96 [2] ad 97 [2] b6 91 [2] aa 96 [2] b6 b9 }

  condition:
    any of them
}