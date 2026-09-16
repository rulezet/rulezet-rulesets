rule TTP_XOR_QUAD_CurrentVersionRun_90e9 {
  strings:
    $key_90e9 = { c3 86 [2] e7 88 [2] cc a4 [2] e2 86 [2] f6 9d [2] f9 87 [2] e7 9a [2] e5 9b [2] fe 9d [2] e2 9a [2] fe b5 }

  condition:
    any of them
}