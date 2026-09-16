rule TTP_XOR_QUAD_CurrentVersionRun_89d7 {
  strings:
    $key_89d7 = { da b8 [2] fe b6 [2] d5 9a [2] fb b8 [2] ef a3 [2] e0 b9 [2] fe a4 [2] fc a5 [2] e7 a3 [2] fb a4 [2] e7 8b }

  condition:
    any of them
}