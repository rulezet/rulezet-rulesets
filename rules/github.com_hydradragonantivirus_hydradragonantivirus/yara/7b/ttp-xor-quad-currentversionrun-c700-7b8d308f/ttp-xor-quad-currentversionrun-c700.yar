rule TTP_XOR_QUAD_CurrentVersionRun_c700 {
  strings:
    $key_c700 = { 94 6f [2] b0 61 [2] 9b 4d [2] b5 6f [2] a1 74 [2] ae 6e [2] b0 73 [2] b2 72 [2] a9 74 [2] b5 73 [2] a9 5c }

  condition:
    any of them
}