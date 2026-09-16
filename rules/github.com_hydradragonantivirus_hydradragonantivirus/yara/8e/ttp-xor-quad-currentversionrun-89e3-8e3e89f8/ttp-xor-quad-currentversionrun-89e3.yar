rule TTP_XOR_QUAD_CurrentVersionRun_89e3 {
  strings:
    $key_89e3 = { da 8c [2] fe 82 [2] d5 ae [2] fb 8c [2] ef 97 [2] e0 8d [2] fe 90 [2] fc 91 [2] e7 97 [2] fb 90 [2] e7 bf }

  condition:
    any of them
}