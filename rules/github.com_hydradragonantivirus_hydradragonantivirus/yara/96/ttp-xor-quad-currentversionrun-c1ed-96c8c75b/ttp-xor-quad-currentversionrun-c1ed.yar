rule TTP_XOR_QUAD_CurrentVersionRun_c1ed {
  strings:
    $key_c1ed = { 92 82 [2] b6 8c [2] 9d a0 [2] b3 82 [2] a7 99 [2] a8 83 [2] b6 9e [2] b4 9f [2] af 99 [2] b3 9e [2] af b1 }

  condition:
    any of them
}