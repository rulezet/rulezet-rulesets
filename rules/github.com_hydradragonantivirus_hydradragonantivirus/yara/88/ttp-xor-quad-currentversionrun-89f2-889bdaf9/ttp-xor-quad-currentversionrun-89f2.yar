rule TTP_XOR_QUAD_CurrentVersionRun_89f2 {
  strings:
    $key_89f2 = { da 9d [2] fe 93 [2] d5 bf [2] fb 9d [2] ef 86 [2] e0 9c [2] fe 81 [2] fc 80 [2] e7 86 [2] fb 81 [2] e7 ae }

  condition:
    any of them
}