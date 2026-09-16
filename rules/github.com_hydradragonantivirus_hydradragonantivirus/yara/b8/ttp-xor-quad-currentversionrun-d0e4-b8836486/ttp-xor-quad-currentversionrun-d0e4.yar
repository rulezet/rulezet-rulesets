rule TTP_XOR_QUAD_CurrentVersionRun_d0e4 {
  strings:
    $key_d0e4 = { 83 8b [2] a7 85 [2] 8c a9 [2] a2 8b [2] b6 90 [2] b9 8a [2] a7 97 [2] a5 96 [2] be 90 [2] a2 97 [2] be b8 }

  condition:
    any of them
}