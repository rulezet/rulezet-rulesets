rule TTP_XOR_QUAD_CurrentVersionRun_d046 {
  strings:
    $key_d046 = { 83 29 [2] a7 27 [2] 8c 0b [2] a2 29 [2] b6 32 [2] b9 28 [2] a7 35 [2] a5 34 [2] be 32 [2] a2 35 [2] be 1a }

  condition:
    any of them
}