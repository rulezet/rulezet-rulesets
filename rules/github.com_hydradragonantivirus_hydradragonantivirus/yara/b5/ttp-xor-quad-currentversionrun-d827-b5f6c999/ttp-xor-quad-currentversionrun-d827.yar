rule TTP_XOR_QUAD_CurrentVersionRun_d827 {
  strings:
    $key_d827 = { 8b 48 [2] af 46 [2] 84 6a [2] aa 48 [2] be 53 [2] b1 49 [2] af 54 [2] ad 55 [2] b6 53 [2] aa 54 [2] b6 7b }

  condition:
    any of them
}