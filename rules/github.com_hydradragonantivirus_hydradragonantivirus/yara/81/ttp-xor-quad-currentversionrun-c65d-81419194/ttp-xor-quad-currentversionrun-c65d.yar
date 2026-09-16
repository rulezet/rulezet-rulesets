rule TTP_XOR_QUAD_CurrentVersionRun_c65d {
  strings:
    $key_c65d = { 95 32 [2] b1 3c [2] 9a 10 [2] b4 32 [2] a0 29 [2] af 33 [2] b1 2e [2] b3 2f [2] a8 29 [2] b4 2e [2] a8 01 }

  condition:
    any of them
}