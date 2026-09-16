rule TTP_XOR_QUAD_CurrentVersionRun_c710 {
  strings:
    $key_c710 = { 94 7f [2] b0 71 [2] 9b 5d [2] b5 7f [2] a1 64 [2] ae 7e [2] b0 63 [2] b2 62 [2] a9 64 [2] b5 63 [2] a9 4c }

  condition:
    any of them
}