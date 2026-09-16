rule TTP_XOR_QUAD_CurrentVersionRun_d0c7 {
  strings:
    $key_d0c7 = { 83 a8 [2] a7 a6 [2] 8c 8a [2] a2 a8 [2] b6 b3 [2] b9 a9 [2] a7 b4 [2] a5 b5 [2] be b3 [2] a2 b4 [2] be 9b }

  condition:
    any of them
}