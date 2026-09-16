rule TTP_XOR_QUAD_CurrentVersionRun_983e {
  strings:
    $key_983e = { cb 51 [2] ef 5f [2] c4 73 [2] ea 51 [2] fe 4a [2] f1 50 [2] ef 4d [2] ed 4c [2] f6 4a [2] ea 4d [2] f6 62 }

  condition:
    any of them
}