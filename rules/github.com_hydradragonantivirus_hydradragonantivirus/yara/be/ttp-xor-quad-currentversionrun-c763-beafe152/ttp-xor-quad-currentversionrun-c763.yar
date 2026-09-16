rule TTP_XOR_QUAD_CurrentVersionRun_c763 {
  strings:
    $key_c763 = { 94 0c [2] b0 02 [2] 9b 2e [2] b5 0c [2] a1 17 [2] ae 0d [2] b0 10 [2] b2 11 [2] a9 17 [2] b5 10 [2] a9 3f }

  condition:
    any of them
}