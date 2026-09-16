rule TTP_XOR_QUAD_CurrentVersionRun_c34f {
  strings:
    $key_c34f = { 90 20 [2] b4 2e [2] 9f 02 [2] b1 20 [2] a5 3b [2] aa 21 [2] b4 3c [2] b6 3d [2] ad 3b [2] b1 3c [2] ad 13 }

  condition:
    any of them
}