rule TTP_XOR_QUAD_CurrentVersionRun_c64a {
  strings:
    $key_c64a = { 95 25 [2] b1 2b [2] 9a 07 [2] b4 25 [2] a0 3e [2] af 24 [2] b1 39 [2] b3 38 [2] a8 3e [2] b4 39 [2] a8 16 }

  condition:
    any of them
}