rule TTP_XOR_QUAD_CurrentVersionRun_90aa {
  strings:
    $key_90aa = { c3 c5 [2] e7 cb [2] cc e7 [2] e2 c5 [2] f6 de [2] f9 c4 [2] e7 d9 [2] e5 d8 [2] fe de [2] e2 d9 [2] fe f6 }

  condition:
    any of them
}