rule TTP_XOR_QUAD_CurrentVersionRun_d079 {
  strings:
    $key_d079 = { 83 16 [2] a7 18 [2] 8c 34 [2] a2 16 [2] b6 0d [2] b9 17 [2] a7 0a [2] a5 0b [2] be 0d [2] a2 0a [2] be 25 }

  condition:
    any of them
}