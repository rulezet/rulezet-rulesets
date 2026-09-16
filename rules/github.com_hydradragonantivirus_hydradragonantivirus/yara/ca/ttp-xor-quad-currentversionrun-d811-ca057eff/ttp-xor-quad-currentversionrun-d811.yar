rule TTP_XOR_QUAD_CurrentVersionRun_d811 {
  strings:
    $key_d811 = { 8b 7e [2] af 70 [2] 84 5c [2] aa 7e [2] be 65 [2] b1 7f [2] af 62 [2] ad 63 [2] b6 65 [2] aa 62 [2] b6 4d }

  condition:
    any of them
}