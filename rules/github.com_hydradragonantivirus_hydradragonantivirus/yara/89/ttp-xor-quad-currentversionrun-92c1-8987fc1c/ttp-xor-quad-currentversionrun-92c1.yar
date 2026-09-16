rule TTP_XOR_QUAD_CurrentVersionRun_92c1 {
  strings:
    $key_92c1 = { c1 ae [2] e5 a0 [2] ce 8c [2] e0 ae [2] f4 b5 [2] fb af [2] e5 b2 [2] e7 b3 [2] fc b5 [2] e0 b2 [2] fc 9d }

  condition:
    any of them
}