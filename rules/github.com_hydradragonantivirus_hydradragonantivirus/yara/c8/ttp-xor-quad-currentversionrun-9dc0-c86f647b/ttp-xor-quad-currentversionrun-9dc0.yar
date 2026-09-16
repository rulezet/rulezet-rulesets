rule TTP_XOR_QUAD_CurrentVersionRun_9dc0 {
  strings:
    $key_9dc0 = { ce af [2] ea a1 [2] c1 8d [2] ef af [2] fb b4 [2] f4 ae [2] ea b3 [2] e8 b2 [2] f3 b4 [2] ef b3 [2] f3 9c }

  condition:
    any of them
}