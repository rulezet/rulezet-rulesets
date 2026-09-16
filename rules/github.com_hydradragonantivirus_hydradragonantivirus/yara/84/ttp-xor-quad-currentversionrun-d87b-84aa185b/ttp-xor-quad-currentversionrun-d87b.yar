rule TTP_XOR_QUAD_CurrentVersionRun_d87b {
  strings:
    $key_d87b = { 8b 14 [2] af 1a [2] 84 36 [2] aa 14 [2] be 0f [2] b1 15 [2] af 08 [2] ad 09 [2] b6 0f [2] aa 08 [2] b6 27 }

  condition:
    any of them
}