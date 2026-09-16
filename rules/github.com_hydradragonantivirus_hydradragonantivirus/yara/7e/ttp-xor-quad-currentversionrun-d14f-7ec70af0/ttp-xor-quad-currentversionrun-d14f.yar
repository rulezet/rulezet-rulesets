rule TTP_XOR_QUAD_CurrentVersionRun_d14f {
  strings:
    $key_d14f = { 82 20 [2] a6 2e [2] 8d 02 [2] a3 20 [2] b7 3b [2] b8 21 [2] a6 3c [2] a4 3d [2] bf 3b [2] a3 3c [2] bf 13 }

  condition:
    any of them
}