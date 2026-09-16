rule TTP_XOR_QUAD_CurrentVersionRun_d857 {
  strings:
    $key_d857 = { 8b 38 [2] af 36 [2] 84 1a [2] aa 38 [2] be 23 [2] b1 39 [2] af 24 [2] ad 25 [2] b6 23 [2] aa 24 [2] b6 0b }

  condition:
    any of them
}