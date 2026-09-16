rule TTP_XOR_QUAD_CurrentVersionRun_981f {
  strings:
    $key_981f = { cb 70 [2] ef 7e [2] c4 52 [2] ea 70 [2] fe 6b [2] f1 71 [2] ef 6c [2] ed 6d [2] f6 6b [2] ea 6c [2] f6 43 }

  condition:
    any of them
}