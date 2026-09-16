rule TTP_XOR_QUAD_CurrentVersionRun_d64d {
  strings:
    $key_d64d = { 85 22 [2] a1 2c [2] 8a 00 [2] a4 22 [2] b0 39 [2] bf 23 [2] a1 3e [2] a3 3f [2] b8 39 [2] a4 3e [2] b8 11 }

  condition:
    any of them
}