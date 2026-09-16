rule TTP_XOR_QUAD_CurrentVersionRun_d820 {
  strings:
    $key_d820 = { 8b 4f [2] af 41 [2] 84 6d [2] aa 4f [2] be 54 [2] b1 4e [2] af 53 [2] ad 52 [2] b6 54 [2] aa 53 [2] b6 7c }

  condition:
    any of them
}