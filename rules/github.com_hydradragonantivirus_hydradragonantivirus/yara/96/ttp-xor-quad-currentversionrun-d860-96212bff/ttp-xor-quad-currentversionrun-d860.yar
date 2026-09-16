rule TTP_XOR_QUAD_CurrentVersionRun_d860 {
  strings:
    $key_d860 = { 8b 0f [2] af 01 [2] 84 2d [2] aa 0f [2] be 14 [2] b1 0e [2] af 13 [2] ad 12 [2] b6 14 [2] aa 13 [2] b6 3c }

  condition:
    any of them
}