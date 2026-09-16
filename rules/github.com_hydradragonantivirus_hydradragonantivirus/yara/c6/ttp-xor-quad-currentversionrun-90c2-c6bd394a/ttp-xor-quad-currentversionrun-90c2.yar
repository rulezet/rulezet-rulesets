rule TTP_XOR_QUAD_CurrentVersionRun_90c2 {
  strings:
    $key_90c2 = { c3 ad [2] e7 a3 [2] cc 8f [2] e2 ad [2] f6 b6 [2] f9 ac [2] e7 b1 [2] e5 b0 [2] fe b6 [2] e2 b1 [2] fe 9e }

  condition:
    any of them
}