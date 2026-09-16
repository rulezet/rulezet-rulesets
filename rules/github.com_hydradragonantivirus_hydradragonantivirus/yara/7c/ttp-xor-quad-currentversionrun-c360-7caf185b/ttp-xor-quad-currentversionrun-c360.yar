rule TTP_XOR_QUAD_CurrentVersionRun_c360 {
  strings:
    $key_c360 = { 90 0f [2] b4 01 [2] 9f 2d [2] b1 0f [2] a5 14 [2] aa 0e [2] b4 13 [2] b6 12 [2] ad 14 [2] b1 13 [2] ad 3c }

  condition:
    any of them
}