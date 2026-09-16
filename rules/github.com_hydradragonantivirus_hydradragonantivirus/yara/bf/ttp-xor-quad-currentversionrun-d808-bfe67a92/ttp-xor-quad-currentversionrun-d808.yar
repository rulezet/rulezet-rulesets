rule TTP_XOR_QUAD_CurrentVersionRun_d808 {
  strings:
    $key_d808 = { 8b 67 [2] af 69 [2] 84 45 [2] aa 67 [2] be 7c [2] b1 66 [2] af 7b [2] ad 7a [2] b6 7c [2] aa 7b [2] b6 54 }

  condition:
    any of them
}