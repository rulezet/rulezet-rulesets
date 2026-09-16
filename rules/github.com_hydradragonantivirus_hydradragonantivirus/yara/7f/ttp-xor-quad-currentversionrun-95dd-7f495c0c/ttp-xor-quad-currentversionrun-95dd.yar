rule TTP_XOR_QUAD_CurrentVersionRun_95dd {
  strings:
    $key_95dd = { c6 b2 [2] e2 bc [2] c9 90 [2] e7 b2 [2] f3 a9 [2] fc b3 [2] e2 ae [2] e0 af [2] fb a9 [2] e7 ae [2] fb 81 }

  condition:
    any of them
}