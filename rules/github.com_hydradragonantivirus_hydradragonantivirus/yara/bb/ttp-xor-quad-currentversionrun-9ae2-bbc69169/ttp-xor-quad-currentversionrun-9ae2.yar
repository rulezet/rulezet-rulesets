rule TTP_XOR_QUAD_CurrentVersionRun_9ae2 {
  strings:
    $key_9ae2 = { c9 8d [2] ed 83 [2] c6 af [2] e8 8d [2] fc 96 [2] f3 8c [2] ed 91 [2] ef 90 [2] f4 96 [2] e8 91 [2] f4 be }

  condition:
    any of them
}