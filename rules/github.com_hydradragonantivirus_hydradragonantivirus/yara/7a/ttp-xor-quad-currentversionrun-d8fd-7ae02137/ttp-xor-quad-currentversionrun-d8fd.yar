rule TTP_XOR_QUAD_CurrentVersionRun_d8fd {
  strings:
    $key_d8fd = { 8b 92 [2] af 9c [2] 84 b0 [2] aa 92 [2] be 89 [2] b1 93 [2] af 8e [2] ad 8f [2] b6 89 [2] aa 8e [2] b6 a1 }

  condition:
    any of them
}