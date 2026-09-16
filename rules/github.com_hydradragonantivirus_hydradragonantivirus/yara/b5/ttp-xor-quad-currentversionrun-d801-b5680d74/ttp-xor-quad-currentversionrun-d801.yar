rule TTP_XOR_QUAD_CurrentVersionRun_d801 {
  strings:
    $key_d801 = { 8b 6e [2] af 60 [2] 84 4c [2] aa 6e [2] be 75 [2] b1 6f [2] af 72 [2] ad 73 [2] b6 75 [2] aa 72 [2] b6 5d }

  condition:
    any of them
}