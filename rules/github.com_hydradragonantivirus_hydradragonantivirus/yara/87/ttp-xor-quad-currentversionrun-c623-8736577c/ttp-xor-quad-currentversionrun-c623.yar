rule TTP_XOR_QUAD_CurrentVersionRun_c623 {
  strings:
    $key_c623 = { 95 4c [2] b1 42 [2] 9a 6e [2] b4 4c [2] a0 57 [2] af 4d [2] b1 50 [2] b3 51 [2] a8 57 [2] b4 50 [2] a8 7f }

  condition:
    any of them
}