rule TTP_XOR_QUAD_CurrentVersionRun_d854 {
  strings:
    $key_d854 = { 8b 3b [2] af 35 [2] 84 19 [2] aa 3b [2] be 20 [2] b1 3a [2] af 27 [2] ad 26 [2] b6 20 [2] aa 27 [2] b6 08 }

  condition:
    any of them
}