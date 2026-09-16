rule TTP_XOR_QUAD_CurrentVersionRun_d81b {
  strings:
    $key_d81b = { 8b 74 [2] af 7a [2] 84 56 [2] aa 74 [2] be 6f [2] b1 75 [2] af 68 [2] ad 69 [2] b6 6f [2] aa 68 [2] b6 47 }

  condition:
    any of them
}