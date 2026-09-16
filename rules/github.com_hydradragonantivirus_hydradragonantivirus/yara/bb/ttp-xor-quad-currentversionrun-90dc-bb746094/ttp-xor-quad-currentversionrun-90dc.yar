rule TTP_XOR_QUAD_CurrentVersionRun_90dc {
  strings:
    $key_90dc = { c3 b3 [2] e7 bd [2] cc 91 [2] e2 b3 [2] f6 a8 [2] f9 b2 [2] e7 af [2] e5 ae [2] fe a8 [2] e2 af [2] fe 80 }

  condition:
    any of them
}