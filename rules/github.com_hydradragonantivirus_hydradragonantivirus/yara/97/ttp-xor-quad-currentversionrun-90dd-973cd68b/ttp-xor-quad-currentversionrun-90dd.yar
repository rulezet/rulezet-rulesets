rule TTP_XOR_QUAD_CurrentVersionRun_90dd {
  strings:
    $key_90dd = { c3 b2 [2] e7 bc [2] cc 90 [2] e2 b2 [2] f6 a9 [2] f9 b3 [2] e7 ae [2] e5 af [2] fe a9 [2] e2 ae [2] fe 81 }

  condition:
    any of them
}