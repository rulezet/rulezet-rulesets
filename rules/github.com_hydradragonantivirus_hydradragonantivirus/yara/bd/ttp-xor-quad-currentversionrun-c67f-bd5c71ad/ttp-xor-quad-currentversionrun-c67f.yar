rule TTP_XOR_QUAD_CurrentVersionRun_c67f {
  strings:
    $key_c67f = { 95 10 [2] b1 1e [2] 9a 32 [2] b4 10 [2] a0 0b [2] af 11 [2] b1 0c [2] b3 0d [2] a8 0b [2] b4 0c [2] a8 23 }

  condition:
    any of them
}