rule TTP_XOR_QUAD_CurrentVersionRun_d055 {
  strings:
    $key_d055 = { 83 3a [2] a7 34 [2] 8c 18 [2] a2 3a [2] b6 21 [2] b9 3b [2] a7 26 [2] a5 27 [2] be 21 [2] a2 26 [2] be 09 }

  condition:
    any of them
}