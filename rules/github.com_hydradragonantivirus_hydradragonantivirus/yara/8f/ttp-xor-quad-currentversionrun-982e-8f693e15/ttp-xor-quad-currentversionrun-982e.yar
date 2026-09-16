rule TTP_XOR_QUAD_CurrentVersionRun_982e {
  strings:
    $key_982e = { cb 41 [2] ef 4f [2] c4 63 [2] ea 41 [2] fe 5a [2] f1 40 [2] ef 5d [2] ed 5c [2] f6 5a [2] ea 5d [2] f6 72 }

  condition:
    any of them
}