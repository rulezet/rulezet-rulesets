rule TTP_XOR_QUAD_CurrentVersionRun_89db {
  strings:
    $key_89db = { da b4 [2] fe ba [2] d5 96 [2] fb b4 [2] ef af [2] e0 b5 [2] fe a8 [2] fc a9 [2] e7 af [2] fb a8 [2] e7 87 }

  condition:
    any of them
}