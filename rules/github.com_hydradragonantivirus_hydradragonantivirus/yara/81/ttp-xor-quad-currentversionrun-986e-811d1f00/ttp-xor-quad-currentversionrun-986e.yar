rule TTP_XOR_QUAD_CurrentVersionRun_986e {
  strings:
    $key_986e = { cb 01 [2] ef 0f [2] c4 23 [2] ea 01 [2] fe 1a [2] f1 00 [2] ef 1d [2] ed 1c [2] f6 1a [2] ea 1d [2] f6 32 }

  condition:
    any of them
}