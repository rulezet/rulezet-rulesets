rule TTP_XOR_QUAD_CurrentVersionRun_90c1 {
  strings:
    $key_90c1 = { c3 ae [2] e7 a0 [2] cc 8c [2] e2 ae [2] f6 b5 [2] f9 af [2] e7 b2 [2] e5 b3 [2] fe b5 [2] e2 b2 [2] fe 9d }

  condition:
    any of them
}