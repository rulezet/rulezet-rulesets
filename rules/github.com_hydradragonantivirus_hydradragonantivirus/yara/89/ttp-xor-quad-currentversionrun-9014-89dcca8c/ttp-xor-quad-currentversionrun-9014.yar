rule TTP_XOR_QUAD_CurrentVersionRun_9014 {
  strings:
    $key_9014 = { c3 7b [2] e7 75 [2] cc 59 [2] e2 7b [2] f6 60 [2] f9 7a [2] e7 67 [2] e5 66 [2] fe 60 [2] e2 67 [2] fe 48 }

  condition:
    any of them
}