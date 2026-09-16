rule TTP_XOR_QUAD_CurrentVersionRun_90a2 {
  strings:
    $key_90a2 = { c3 cd [2] e7 c3 [2] cc ef [2] e2 cd [2] f6 d6 [2] f9 cc [2] e7 d1 [2] e5 d0 [2] fe d6 [2] e2 d1 [2] fe fe }

  condition:
    any of them
}