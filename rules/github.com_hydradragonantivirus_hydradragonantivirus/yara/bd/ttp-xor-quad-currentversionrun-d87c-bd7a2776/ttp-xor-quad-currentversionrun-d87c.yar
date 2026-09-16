rule TTP_XOR_QUAD_CurrentVersionRun_d87c {
  strings:
    $key_d87c = { 8b 13 [2] af 1d [2] 84 31 [2] aa 13 [2] be 08 [2] b1 12 [2] af 0f [2] ad 0e [2] b6 08 [2] aa 0f [2] b6 20 }

  condition:
    any of them
}