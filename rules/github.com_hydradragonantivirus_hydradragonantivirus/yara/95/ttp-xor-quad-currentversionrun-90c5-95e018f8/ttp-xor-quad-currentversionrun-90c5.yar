rule TTP_XOR_QUAD_CurrentVersionRun_90c5 {
  strings:
    $key_90c5 = { c3 aa [2] e7 a4 [2] cc 88 [2] e2 aa [2] f6 b1 [2] f9 ab [2] e7 b6 [2] e5 b7 [2] fe b1 [2] e2 b6 [2] fe 99 }

  condition:
    any of them
}