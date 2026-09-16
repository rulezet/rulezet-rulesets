rule TTP_XOR_QUAD_CurrentVersionRun_c730 {
  strings:
    $key_c730 = { 94 5f [2] b0 51 [2] 9b 7d [2] b5 5f [2] a1 44 [2] ae 5e [2] b0 43 [2] b2 42 [2] a9 44 [2] b5 43 [2] a9 6c }

  condition:
    any of them
}