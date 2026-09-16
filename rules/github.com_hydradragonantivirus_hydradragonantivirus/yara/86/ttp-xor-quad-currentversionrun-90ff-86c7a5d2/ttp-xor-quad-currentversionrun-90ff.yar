rule TTP_XOR_QUAD_CurrentVersionRun_90ff {
  strings:
    $key_90ff = { c3 90 [2] e7 9e [2] cc b2 [2] e2 90 [2] f6 8b [2] f9 91 [2] e7 8c [2] e5 8d [2] fe 8b [2] e2 8c [2] fe a3 }

  condition:
    any of them
}