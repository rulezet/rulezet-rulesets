rule TTP_XOR_QUAD_CurrentVersionRun_97d8 {
  strings:
    $key_97d8 = { c4 b7 [2] e0 b9 [2] cb 95 [2] e5 b7 [2] f1 ac [2] fe b6 [2] e0 ab [2] e2 aa [2] f9 ac [2] e5 ab [2] f9 84 }

  condition:
    any of them
}