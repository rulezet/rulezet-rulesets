rule TTP_XOR_QUAD_CurrentVersionRun_97ff {
  strings:
    $key_97ff = { c4 90 [2] e0 9e [2] cb b2 [2] e5 90 [2] f1 8b [2] fe 91 [2] e0 8c [2] e2 8d [2] f9 8b [2] e5 8c [2] f9 a3 }

  condition:
    any of them
}