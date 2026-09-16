rule TTP_XOR_QUAD_CurrentVersionRun_89c7 {
  strings:
    $key_89c7 = { da a8 [2] fe a6 [2] d5 8a [2] fb a8 [2] ef b3 [2] e0 a9 [2] fe b4 [2] fc b5 [2] e7 b3 [2] fb b4 [2] e7 9b }

  condition:
    any of them
}