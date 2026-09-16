rule TTP_XOR_QUAD_CurrentVersionRun_9add {
  strings:
    $key_9add = { c9 b2 [2] ed bc [2] c6 90 [2] e8 b2 [2] fc a9 [2] f3 b3 [2] ed ae [2] ef af [2] f4 a9 [2] e8 ae [2] f4 81 }

  condition:
    any of them
}