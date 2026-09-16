rule TTP_XOR_QUAD_CurrentVersionRun_c63f {
  strings:
    $key_c63f = { 95 50 [2] b1 5e [2] 9a 72 [2] b4 50 [2] a0 4b [2] af 51 [2] b1 4c [2] b3 4d [2] a8 4b [2] b4 4c [2] a8 63 }

  condition:
    any of them
}