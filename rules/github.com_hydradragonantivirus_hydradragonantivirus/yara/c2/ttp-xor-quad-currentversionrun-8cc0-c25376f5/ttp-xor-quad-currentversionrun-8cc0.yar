rule TTP_XOR_QUAD_CurrentVersionRun_8cc0 {
  strings:
    $key_8cc0 = { df af [2] fb a1 [2] d0 8d [2] fe af [2] ea b4 [2] e5 ae [2] fb b3 [2] f9 b2 [2] e2 b4 [2] fe b3 [2] e2 9c }

  condition:
    any of them
}