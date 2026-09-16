rule TTP_XOR_QUAD_CurrentVersionRun_d869 {
  strings:
    $key_d869 = { 8b 06 [2] af 08 [2] 84 24 [2] aa 06 [2] be 1d [2] b1 07 [2] af 1a [2] ad 1b [2] b6 1d [2] aa 1a [2] b6 35 }

  condition:
    any of them
}