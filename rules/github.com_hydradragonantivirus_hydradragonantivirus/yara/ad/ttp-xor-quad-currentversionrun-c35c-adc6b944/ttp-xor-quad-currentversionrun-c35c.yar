rule TTP_XOR_QUAD_CurrentVersionRun_c35c {
  strings:
    $key_c35c = { 90 33 [2] b4 3d [2] 9f 11 [2] b1 33 [2] a5 28 [2] aa 32 [2] b4 2f [2] b6 2e [2] ad 28 [2] b1 2f [2] ad 00 }

  condition:
    any of them
}