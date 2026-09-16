rule TTP_XOR_QUAD_CurrentVersionRun_981e {
  strings:
    $key_981e = { cb 71 [2] ef 7f [2] c4 53 [2] ea 71 [2] fe 6a [2] f1 70 [2] ef 6d [2] ed 6c [2] f6 6a [2] ea 6d [2] f6 42 }

  condition:
    any of them
}