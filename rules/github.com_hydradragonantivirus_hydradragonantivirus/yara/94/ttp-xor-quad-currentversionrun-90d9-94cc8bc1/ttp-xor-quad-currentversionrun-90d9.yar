rule TTP_XOR_QUAD_CurrentVersionRun_90d9 {
  strings:
    $key_90d9 = { c3 b6 [2] e7 b8 [2] cc 94 [2] e2 b6 [2] f6 ad [2] f9 b7 [2] e7 aa [2] e5 ab [2] fe ad [2] e2 aa [2] fe 85 }

  condition:
    any of them
}