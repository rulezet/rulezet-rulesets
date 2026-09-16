rule TTP_XOR_QUAD_CurrentVersionRun_89d0 {
  strings:
    $key_89d0 = { da bf [2] fe b1 [2] d5 9d [2] fb bf [2] ef a4 [2] e0 be [2] fe a3 [2] fc a2 [2] e7 a4 [2] fb a3 [2] e7 8c }

  condition:
    any of them
}