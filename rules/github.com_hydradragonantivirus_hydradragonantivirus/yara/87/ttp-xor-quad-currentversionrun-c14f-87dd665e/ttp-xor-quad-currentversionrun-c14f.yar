rule TTP_XOR_QUAD_CurrentVersionRun_c14f {
  strings:
    $key_c14f = { 92 20 [2] b6 2e [2] 9d 02 [2] b3 20 [2] a7 3b [2] a8 21 [2] b6 3c [2] b4 3d [2] af 3b [2] b3 3c [2] af 13 }

  condition:
    any of them
}