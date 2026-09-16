rule TTP_XOR_QUAD_CurrentVersionRun_90b8 {
  strings:
    $key_90b8 = { c3 d7 [2] e7 d9 [2] cc f5 [2] e2 d7 [2] f6 cc [2] f9 d6 [2] e7 cb [2] e5 ca [2] fe cc [2] e2 cb [2] fe e4 }

  condition:
    any of them
}