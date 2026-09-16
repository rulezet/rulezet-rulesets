rule TTP_XOR_QUAD_CurrentVersionRun_d04b {
  strings:
    $key_d04b = { 83 24 [2] a7 2a [2] 8c 06 [2] a2 24 [2] b6 3f [2] b9 25 [2] a7 38 [2] a5 39 [2] be 3f [2] a2 38 [2] be 17 }

  condition:
    any of them
}