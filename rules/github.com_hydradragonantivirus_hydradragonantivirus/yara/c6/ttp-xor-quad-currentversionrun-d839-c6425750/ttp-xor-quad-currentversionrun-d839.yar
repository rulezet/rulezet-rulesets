rule TTP_XOR_QUAD_CurrentVersionRun_d839 {
  strings:
    $key_d839 = { 8b 56 [2] af 58 [2] 84 74 [2] aa 56 [2] be 4d [2] b1 57 [2] af 4a [2] ad 4b [2] b6 4d [2] aa 4a [2] b6 65 }

  condition:
    any of them
}