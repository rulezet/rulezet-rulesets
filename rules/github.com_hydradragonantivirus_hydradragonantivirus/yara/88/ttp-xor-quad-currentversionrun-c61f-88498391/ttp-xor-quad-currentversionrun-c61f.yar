rule TTP_XOR_QUAD_CurrentVersionRun_c61f {
  strings:
    $key_c61f = { 95 70 [2] b1 7e [2] 9a 52 [2] b4 70 [2] a0 6b [2] af 71 [2] b1 6c [2] b3 6d [2] a8 6b [2] b4 6c [2] a8 43 }

  condition:
    any of them
}