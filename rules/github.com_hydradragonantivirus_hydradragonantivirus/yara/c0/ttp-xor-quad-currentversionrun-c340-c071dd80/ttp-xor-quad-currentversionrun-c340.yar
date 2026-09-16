rule TTP_XOR_QUAD_CurrentVersionRun_c340 {
  strings:
    $key_c340 = { 90 2f [2] b4 21 [2] 9f 0d [2] b1 2f [2] a5 34 [2] aa 2e [2] b4 33 [2] b6 32 [2] ad 34 [2] b1 33 [2] ad 1c }

  condition:
    any of them
}