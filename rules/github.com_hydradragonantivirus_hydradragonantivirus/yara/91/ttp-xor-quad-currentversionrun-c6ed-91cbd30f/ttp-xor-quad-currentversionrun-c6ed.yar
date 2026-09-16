rule TTP_XOR_QUAD_CurrentVersionRun_c6ed {
  strings:
    $key_c6ed = { 95 82 [2] b1 8c [2] 9a a0 [2] b4 82 [2] a0 99 [2] af 83 [2] b1 9e [2] b3 9f [2] a8 99 [2] b4 9e [2] a8 b1 }

  condition:
    any of them
}