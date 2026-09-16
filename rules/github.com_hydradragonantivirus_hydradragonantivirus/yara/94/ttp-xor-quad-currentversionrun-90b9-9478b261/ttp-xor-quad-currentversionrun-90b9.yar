rule TTP_XOR_QUAD_CurrentVersionRun_90b9 {
  strings:
    $key_90b9 = { c3 d6 [2] e7 d8 [2] cc f4 [2] e2 d6 [2] f6 cd [2] f9 d7 [2] e7 ca [2] e5 cb [2] fe cd [2] e2 ca [2] fe e5 }

  condition:
    any of them
}