rule TTP_XOR_QUAD_CurrentVersionRun_89e2 {
  strings:
    $key_89e2 = { da 8d [2] fe 83 [2] d5 af [2] fb 8d [2] ef 96 [2] e0 8c [2] fe 91 [2] fc 90 [2] e7 96 [2] fb 91 [2] e7 be }

  condition:
    any of them
}