rule TTP_XOR_QUAD_CurrentVersionRun_89ca {
  strings:
    $key_89ca = { da a5 [2] fe ab [2] d5 87 [2] fb a5 [2] ef be [2] e0 a4 [2] fe b9 [2] fc b8 [2] e7 be [2] fb b9 [2] e7 96 }

  condition:
    any of them
}