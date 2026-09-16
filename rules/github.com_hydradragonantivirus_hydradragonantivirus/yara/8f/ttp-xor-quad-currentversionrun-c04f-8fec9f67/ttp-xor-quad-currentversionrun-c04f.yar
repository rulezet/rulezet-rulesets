rule TTP_XOR_QUAD_CurrentVersionRun_c04f {
  strings:
    $key_c04f = { 93 20 [2] b7 2e [2] 9c 02 [2] b2 20 [2] a6 3b [2] a9 21 [2] b7 3c [2] b5 3d [2] ae 3b [2] b2 3c [2] ae 13 }

  condition:
    any of them
}