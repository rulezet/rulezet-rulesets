rule TTP_XOR_QUAD_CurrentVersionRun_d875 {
  strings:
    $key_d875 = { 8b 1a [2] af 14 [2] 84 38 [2] aa 1a [2] be 01 [2] b1 1b [2] af 06 [2] ad 07 [2] b6 01 [2] aa 06 [2] b6 29 }

  condition:
    any of them
}