rule TTP_XOR_QUAD_CurrentVersionRun_c352 {
  strings:
    $key_c352 = { 90 3d [2] b4 33 [2] 9f 1f [2] b1 3d [2] a5 26 [2] aa 3c [2] b4 21 [2] b6 20 [2] ad 26 [2] b1 21 [2] ad 0e }

  condition:
    any of them
}