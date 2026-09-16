rule TTP_XOR_QUAD_CurrentVersionRun_d064 {
  strings:
    $key_d064 = { 83 0b [2] a7 05 [2] 8c 29 [2] a2 0b [2] b6 10 [2] b9 0a [2] a7 17 [2] a5 16 [2] be 10 [2] a2 17 [2] be 38 }

  condition:
    any of them
}