rule TTP_XOR_QUAD_CurrentVersionRun_90e2 {
  strings:
    $key_90e2 = { c3 8d [2] e7 83 [2] cc af [2] e2 8d [2] f6 96 [2] f9 8c [2] e7 91 [2] e5 90 [2] fe 96 [2] e2 91 [2] fe be }

  condition:
    any of them
}