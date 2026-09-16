rule TTP_XOR_QUAD_CurrentVersionRun_c041 {
  strings:
    $key_c041 = { 93 2e [2] b7 20 [2] 9c 0c [2] b2 2e [2] a6 35 [2] a9 2f [2] b7 32 [2] b5 33 [2] ae 35 [2] b2 32 [2] ae 1d }

  condition:
    any of them
}