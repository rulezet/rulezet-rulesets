rule TTP_XOR_QUAD_CurrentVersionRun_90f5 {
  strings:
    $key_90f5 = { c3 9a [2] e7 94 [2] cc b8 [2] e2 9a [2] f6 81 [2] f9 9b [2] e7 86 [2] e5 87 [2] fe 81 [2] e2 86 [2] fe a9 }

  condition:
    any of them
}