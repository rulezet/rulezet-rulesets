rule TTP_XOR_QUAD_CurrentVersionRun_c67d {
  strings:
    $key_c67d = { 95 12 [2] b1 1c [2] 9a 30 [2] b4 12 [2] a0 09 [2] af 13 [2] b1 0e [2] b3 0f [2] a8 09 [2] b4 0e [2] a8 21 }

  condition:
    any of them
}