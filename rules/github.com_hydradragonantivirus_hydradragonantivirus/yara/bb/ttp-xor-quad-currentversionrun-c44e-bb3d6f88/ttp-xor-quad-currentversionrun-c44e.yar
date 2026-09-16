rule TTP_XOR_QUAD_CurrentVersionRun_c44e {
  strings:
    $key_c44e = { 97 21 [2] b3 2f [2] 98 03 [2] b6 21 [2] a2 3a [2] ad 20 [2] b3 3d [2] b1 3c [2] aa 3a [2] b6 3d [2] aa 12 }

  condition:
    any of them
}