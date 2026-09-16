rule TTP_XOR_QUAD_CurrentVersionRun_c633 {
  strings:
    $key_c633 = { 95 5c [2] b1 52 [2] 9a 7e [2] b4 5c [2] a0 47 [2] af 5d [2] b1 40 [2] b3 41 [2] a8 47 [2] b4 40 [2] a8 6f }

  condition:
    any of them
}