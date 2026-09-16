rule TTP_XOR_QUAD_CurrentVersionRun_c74e {
  strings:
    $key_c74e = { 94 21 [2] b0 2f [2] 9b 03 [2] b5 21 [2] a1 3a [2] ae 20 [2] b0 3d [2] b2 3c [2] a9 3a [2] b5 3d [2] a9 12 }

  condition:
    any of them
}