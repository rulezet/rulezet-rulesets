rule TTP_XOR_QUAD_CurrentVersionRun_d8f9 {
  strings:
    $key_d8f9 = { 8b 96 [2] af 98 [2] 84 b4 [2] aa 96 [2] be 8d [2] b1 97 [2] af 8a [2] ad 8b [2] b6 8d [2] aa 8a [2] b6 a5 }

  condition:
    any of them
}