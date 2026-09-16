rule TTP_XOR_QUAD_CurrentVersionRun_d014 {
  strings:
    $key_d014 = { 83 7b [2] a7 75 [2] 8c 59 [2] a2 7b [2] b6 60 [2] b9 7a [2] a7 67 [2] a5 66 [2] be 60 [2] a2 67 [2] be 48 }

  condition:
    any of them
}