rule TTP_XOR_QUAD_CurrentVersionRun_97fc {
  strings:
    $key_97fc = { c4 93 [2] e0 9d [2] cb b1 [2] e5 93 [2] f1 88 [2] fe 92 [2] e0 8f [2] e2 8e [2] f9 88 [2] e5 8f [2] f9 a0 }

  condition:
    any of them
}