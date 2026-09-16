rule TTP_XOR_QUAD_CurrentVersionRun_90f9 {
  strings:
    $key_90f9 = { c3 96 [2] e7 98 [2] cc b4 [2] e2 96 [2] f6 8d [2] f9 97 [2] e7 8a [2] e5 8b [2] fe 8d [2] e2 8a [2] fe a5 }

  condition:
    any of them
}