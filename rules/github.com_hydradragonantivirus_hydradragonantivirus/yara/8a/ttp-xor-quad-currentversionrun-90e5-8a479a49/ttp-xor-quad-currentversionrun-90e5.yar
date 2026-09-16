rule TTP_XOR_QUAD_CurrentVersionRun_90e5 {
  strings:
    $key_90e5 = { c3 8a [2] e7 84 [2] cc a8 [2] e2 8a [2] f6 91 [2] f9 8b [2] e7 96 [2] e5 97 [2] fe 91 [2] e2 96 [2] fe b9 }

  condition:
    any of them
}