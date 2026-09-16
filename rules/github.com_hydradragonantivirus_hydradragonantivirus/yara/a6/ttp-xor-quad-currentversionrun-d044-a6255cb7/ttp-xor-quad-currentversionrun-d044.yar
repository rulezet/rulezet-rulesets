rule TTP_XOR_QUAD_CurrentVersionRun_d044 {
  strings:
    $key_d044 = { 83 2b [2] a7 25 [2] 8c 09 [2] a2 2b [2] b6 30 [2] b9 2a [2] a7 37 [2] a5 36 [2] be 30 [2] a2 37 [2] be 18 }

  condition:
    any of them
}