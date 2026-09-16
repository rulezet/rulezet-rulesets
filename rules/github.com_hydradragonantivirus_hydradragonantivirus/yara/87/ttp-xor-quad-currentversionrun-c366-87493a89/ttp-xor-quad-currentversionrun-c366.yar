rule TTP_XOR_QUAD_CurrentVersionRun_c366 {
  strings:
    $key_c366 = { 90 09 [2] b4 07 [2] 9f 2b [2] b1 09 [2] a5 12 [2] aa 08 [2] b4 15 [2] b6 14 [2] ad 12 [2] b1 15 [2] ad 3a }

  condition:
    any of them
}