rule TTP_XOR_QUAD_CurrentVersionRun_c44f {
  strings:
    $key_c44f = { 97 20 [2] b3 2e [2] 98 02 [2] b6 20 [2] a2 3b [2] ad 21 [2] b3 3c [2] b1 3d [2] aa 3b [2] b6 3c [2] aa 13 }

  condition:
    any of them
}