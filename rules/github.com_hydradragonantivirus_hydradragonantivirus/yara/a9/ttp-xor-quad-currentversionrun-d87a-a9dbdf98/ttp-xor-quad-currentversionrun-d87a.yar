rule TTP_XOR_QUAD_CurrentVersionRun_d87a {
  strings:
    $key_d87a = { 8b 15 [2] af 1b [2] 84 37 [2] aa 15 [2] be 0e [2] b1 14 [2] af 09 [2] ad 08 [2] b6 0e [2] aa 09 [2] b6 26 }

  condition:
    any of them
}