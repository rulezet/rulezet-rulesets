rule TTP_XOR_QUAD_CurrentVersionRun_d8e9 {
  strings:
    $key_d8e9 = { 8b 86 [2] af 88 [2] 84 a4 [2] aa 86 [2] be 9d [2] b1 87 [2] af 9a [2] ad 9b [2] b6 9d [2] aa 9a [2] b6 b5 }

  condition:
    any of them
}