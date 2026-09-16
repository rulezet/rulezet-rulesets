rule TTP_XOR_QUAD_CurrentVersionRun_c720 {
  strings:
    $key_c720 = { 94 4f [2] b0 41 [2] 9b 6d [2] b5 4f [2] a1 54 [2] ae 4e [2] b0 53 [2] b2 52 [2] a9 54 [2] b5 53 [2] a9 7c }

  condition:
    any of them
}