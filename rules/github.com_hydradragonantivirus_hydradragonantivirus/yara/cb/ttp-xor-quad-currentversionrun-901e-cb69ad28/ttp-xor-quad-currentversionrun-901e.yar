rule TTP_XOR_QUAD_CurrentVersionRun_901e {
  strings:
    $key_901e = { c3 71 [2] e7 7f [2] cc 53 [2] e2 71 [2] f6 6a [2] f9 70 [2] e7 6d [2] e5 6c [2] fe 6a [2] e2 6d [2] fe 42 }

  condition:
    any of them
}