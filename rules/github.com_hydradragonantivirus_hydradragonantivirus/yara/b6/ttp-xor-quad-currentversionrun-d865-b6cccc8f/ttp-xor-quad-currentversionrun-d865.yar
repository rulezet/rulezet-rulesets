rule TTP_XOR_QUAD_CurrentVersionRun_d865 {
  strings:
    $key_d865 = { 8b 0a [2] af 04 [2] 84 28 [2] aa 0a [2] be 11 [2] b1 0b [2] af 16 [2] ad 17 [2] b6 11 [2] aa 16 [2] b6 39 }

  condition:
    any of them
}