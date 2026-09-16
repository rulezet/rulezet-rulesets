rule TTP_XOR_QUAD_CurrentVersionRun_98be {
  strings:
    $key_98be = { cb d1 [2] ef df [2] c4 f3 [2] ea d1 [2] fe ca [2] f1 d0 [2] ef cd [2] ed cc [2] f6 ca [2] ea cd [2] f6 e2 }

  condition:
    any of them
}