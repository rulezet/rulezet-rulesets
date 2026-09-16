rule TTP_XOR_QUAD_CurrentVersionRun_86e3 {
  strings:
    $key_86e3 = { d5 8c [2] f1 82 [2] da ae [2] f4 8c [2] e0 97 [2] ef 8d [2] f1 90 [2] f3 91 [2] e8 97 [2] f4 90 [2] e8 bf }

  condition:
    any of them
}