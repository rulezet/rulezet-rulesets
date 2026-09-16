rule TTP_XOR_QUAD_CurrentVersionRun_98e3 {
  strings:
    $key_98e3 = { cb 8c [2] ef 82 [2] c4 ae [2] ea 8c [2] fe 97 [2] f1 8d [2] ef 90 [2] ed 91 [2] f6 97 [2] ea 90 [2] f6 bf }

  condition:
    any of them
}