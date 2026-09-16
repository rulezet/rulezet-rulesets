rule TTP_XOR_QUAD_CurrentVersionRun_98dd {
  strings:
    $key_98dd = { cb b2 [2] ef bc [2] c4 90 [2] ea b2 [2] fe a9 [2] f1 b3 [2] ef ae [2] ed af [2] f6 a9 [2] ea ae [2] f6 81 }

  condition:
    any of them
}