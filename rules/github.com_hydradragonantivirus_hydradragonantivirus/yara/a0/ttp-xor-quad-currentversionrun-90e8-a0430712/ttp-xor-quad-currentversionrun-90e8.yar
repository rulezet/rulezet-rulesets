rule TTP_XOR_QUAD_CurrentVersionRun_90e8 {
  strings:
    $key_90e8 = { c3 87 [2] e7 89 [2] cc a5 [2] e2 87 [2] f6 9c [2] f9 86 [2] e7 9b [2] e5 9a [2] fe 9c [2] e2 9b [2] fe b4 }

  condition:
    any of them
}