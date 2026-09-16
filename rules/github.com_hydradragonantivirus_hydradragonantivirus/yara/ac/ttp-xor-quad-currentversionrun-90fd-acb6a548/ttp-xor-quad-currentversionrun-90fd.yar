rule TTP_XOR_QUAD_CurrentVersionRun_90fd {
  strings:
    $key_90fd = { c3 92 [2] e7 9c [2] cc b0 [2] e2 92 [2] f6 89 [2] f9 93 [2] e7 8e [2] e5 8f [2] fe 89 [2] e2 8e [2] fe a1 }

  condition:
    any of them
}