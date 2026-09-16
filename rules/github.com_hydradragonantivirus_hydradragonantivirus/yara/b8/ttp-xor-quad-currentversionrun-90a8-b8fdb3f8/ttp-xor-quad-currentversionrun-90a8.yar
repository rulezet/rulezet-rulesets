rule TTP_XOR_QUAD_CurrentVersionRun_90a8 {
  strings:
    $key_90a8 = { c3 c7 [2] e7 c9 [2] cc e5 [2] e2 c7 [2] f6 dc [2] f9 c6 [2] e7 db [2] e5 da [2] fe dc [2] e2 db [2] fe f4 }

  condition:
    any of them
}