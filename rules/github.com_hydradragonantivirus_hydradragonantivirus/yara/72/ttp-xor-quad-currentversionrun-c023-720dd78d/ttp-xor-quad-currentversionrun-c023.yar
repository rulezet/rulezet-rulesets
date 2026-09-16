rule TTP_XOR_QUAD_CurrentVersionRun_c023 {
  strings:
    $key_c023 = { 93 4c [2] b7 42 [2] 9c 6e [2] b2 4c [2] a6 57 [2] a9 4d [2] b7 50 [2] b5 51 [2] ae 57 [2] b2 50 [2] ae 7f }

  condition:
    any of them
}