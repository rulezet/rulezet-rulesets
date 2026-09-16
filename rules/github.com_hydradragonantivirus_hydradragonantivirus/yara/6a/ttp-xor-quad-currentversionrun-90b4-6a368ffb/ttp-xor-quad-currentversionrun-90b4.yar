rule TTP_XOR_QUAD_CurrentVersionRun_90b4 {
  strings:
    $key_90b4 = { c3 db [2] e7 d5 [2] cc f9 [2] e2 db [2] f6 c0 [2] f9 da [2] e7 c7 [2] e5 c6 [2] fe c0 [2] e2 c7 [2] fe e8 }

  condition:
    any of them
}