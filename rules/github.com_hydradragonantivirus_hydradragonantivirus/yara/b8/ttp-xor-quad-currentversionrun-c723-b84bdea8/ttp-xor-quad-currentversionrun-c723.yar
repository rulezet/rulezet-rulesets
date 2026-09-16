rule TTP_XOR_QUAD_CurrentVersionRun_c723 {
  strings:
    $key_c723 = { 94 4c [2] b0 42 [2] 9b 6e [2] b5 4c [2] a1 57 [2] ae 4d [2] b0 50 [2] b2 51 [2] a9 57 [2] b5 50 [2] a9 7f }

  condition:
    any of them
}