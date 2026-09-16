rule TTP_XOR_QUAD_CurrentVersionRun_c62d {
  strings:
    $key_c62d = { 95 42 [2] b1 4c [2] 9a 60 [2] b4 42 [2] a0 59 [2] af 43 [2] b1 5e [2] b3 5f [2] a8 59 [2] b4 5e [2] a8 71 }

  condition:
    any of them
}