rule TTP_XOR_QUAD_CurrentVersionRun_c630 {
  strings:
    $key_c630 = { 95 5f [2] b1 51 [2] 9a 7d [2] b4 5f [2] a0 44 [2] af 5e [2] b1 43 [2] b3 42 [2] a8 44 [2] b4 43 [2] a8 6c }

  condition:
    any of them
}