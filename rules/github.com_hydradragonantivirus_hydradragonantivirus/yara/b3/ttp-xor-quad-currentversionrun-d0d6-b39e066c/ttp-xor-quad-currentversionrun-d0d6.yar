rule TTP_XOR_QUAD_CurrentVersionRun_d0d6 {
  strings:
    $key_d0d6 = { 83 b9 [2] a7 b7 [2] 8c 9b [2] a2 b9 [2] b6 a2 [2] b9 b8 [2] a7 a5 [2] a5 a4 [2] be a2 [2] a2 a5 [2] be 8a }

  condition:
    any of them
}