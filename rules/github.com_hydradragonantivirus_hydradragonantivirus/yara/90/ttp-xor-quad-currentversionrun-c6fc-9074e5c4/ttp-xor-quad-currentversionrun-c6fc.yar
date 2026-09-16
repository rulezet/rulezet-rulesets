rule TTP_XOR_QUAD_CurrentVersionRun_c6fc {
  strings:
    $key_c6fc = { 95 93 [2] b1 9d [2] 9a b1 [2] b4 93 [2] a0 88 [2] af 92 [2] b1 8f [2] b3 8e [2] a8 88 [2] b4 8f [2] a8 a0 }

  condition:
    any of them
}