rule TTP_XOR_QUAD_CurrentVersionRun_908b {
  strings:
    $key_908b = { c3 e4 [2] e7 ea [2] cc c6 [2] e2 e4 [2] f6 ff [2] f9 e5 [2] e7 f8 [2] e5 f9 [2] fe ff [2] e2 f8 [2] fe d7 }

  condition:
    any of them
}