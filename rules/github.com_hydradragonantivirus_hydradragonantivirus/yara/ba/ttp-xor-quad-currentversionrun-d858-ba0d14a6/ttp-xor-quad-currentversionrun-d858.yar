rule TTP_XOR_QUAD_CurrentVersionRun_d858 {
  strings:
    $key_d858 = { 8b 37 [2] af 39 [2] 84 15 [2] aa 37 [2] be 2c [2] b1 36 [2] af 2b [2] ad 2a [2] b6 2c [2] aa 2b [2] b6 04 }

  condition:
    any of them
}