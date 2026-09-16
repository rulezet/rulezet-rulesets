rule TTP_XOR_QUAD_CurrentVersionRun_d8e1 {
  strings:
    $key_d8e1 = { 8b 8e [2] af 80 [2] 84 ac [2] aa 8e [2] be 95 [2] b1 8f [2] af 92 [2] ad 93 [2] b6 95 [2] aa 92 [2] b6 bd }

  condition:
    any of them
}