rule TTP_XOR_QUAD_CurrentVersionRun_c45c {
  strings:
    $key_c45c = { 97 33 [2] b3 3d [2] 98 11 [2] b6 33 [2] a2 28 [2] ad 32 [2] b3 2f [2] b1 2e [2] aa 28 [2] b6 2f [2] aa 00 }

  condition:
    any of them
}