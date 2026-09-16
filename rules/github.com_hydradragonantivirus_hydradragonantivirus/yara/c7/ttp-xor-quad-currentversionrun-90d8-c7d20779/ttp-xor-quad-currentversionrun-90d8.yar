rule TTP_XOR_QUAD_CurrentVersionRun_90d8 {
  strings:
    $key_90d8 = { c3 b7 [2] e7 b9 [2] cc 95 [2] e2 b7 [2] f6 ac [2] f9 b6 [2] e7 ab [2] e5 aa [2] fe ac [2] e2 ab [2] fe 84 }

  condition:
    any of them
}