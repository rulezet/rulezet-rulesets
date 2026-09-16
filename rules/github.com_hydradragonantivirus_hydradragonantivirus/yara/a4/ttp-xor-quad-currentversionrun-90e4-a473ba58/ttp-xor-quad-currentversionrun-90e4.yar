rule TTP_XOR_QUAD_CurrentVersionRun_90e4 {
  strings:
    $key_90e4 = { c3 8b [2] e7 85 [2] cc a9 [2] e2 8b [2] f6 90 [2] f9 8a [2] e7 97 [2] e5 96 [2] fe 90 [2] e2 97 [2] fe b8 }

  condition:
    any of them
}