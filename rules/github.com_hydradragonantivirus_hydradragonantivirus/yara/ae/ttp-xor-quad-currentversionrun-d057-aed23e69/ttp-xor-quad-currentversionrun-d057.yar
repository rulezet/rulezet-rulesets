rule TTP_XOR_QUAD_CurrentVersionRun_d057 {
  strings:
    $key_d057 = { 83 38 [2] a7 36 [2] 8c 1a [2] a2 38 [2] b6 23 [2] b9 39 [2] a7 24 [2] a5 25 [2] be 23 [2] a2 24 [2] be 0b }

  condition:
    any of them
}