rule TTP_XOR_QUAD_CurrentVersionRun_9dd8 {
  strings:
    $key_9dd8 = { ce b7 [2] ea b9 [2] c1 95 [2] ef b7 [2] fb ac [2] f4 b6 [2] ea ab [2] e8 aa [2] f3 ac [2] ef ab [2] f3 84 }

  condition:
    any of them
}