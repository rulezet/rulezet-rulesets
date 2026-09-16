rule TTP_XOR_QUAD_CurrentVersionRun_c6e6 {
  strings:
    $key_c6e6 = { 95 89 [2] b1 87 [2] 9a ab [2] b4 89 [2] a0 92 [2] af 88 [2] b1 95 [2] b3 94 [2] a8 92 [2] b4 95 [2] a8 ba }

  condition:
    any of them
}