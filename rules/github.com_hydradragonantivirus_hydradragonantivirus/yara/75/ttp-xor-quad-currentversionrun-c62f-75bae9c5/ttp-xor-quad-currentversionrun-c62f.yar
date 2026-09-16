rule TTP_XOR_QUAD_CurrentVersionRun_c62f {
  strings:
    $key_c62f = { 95 40 [2] b1 4e [2] 9a 62 [2] b4 40 [2] a0 5b [2] af 41 [2] b1 5c [2] b3 5d [2] a8 5b [2] b4 5c [2] a8 73 }

  condition:
    any of them
}