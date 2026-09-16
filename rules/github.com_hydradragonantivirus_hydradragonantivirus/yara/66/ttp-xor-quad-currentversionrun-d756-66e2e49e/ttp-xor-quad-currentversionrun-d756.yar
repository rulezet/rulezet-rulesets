rule TTP_XOR_QUAD_CurrentVersionRun_d756 {
  strings:
    $key_d756 = { 84 39 [2] a0 37 [2] 8b 1b [2] a5 39 [2] b1 22 [2] be 38 [2] a0 25 [2] a2 24 [2] b9 22 [2] a5 25 [2] b9 0a }

  condition:
    any of them
}