rule TTP_XOR_QUAD_CurrentVersionRun_8982 {
  strings:
    $key_8982 = { da ed [2] fe e3 [2] d5 cf [2] fb ed [2] ef f6 [2] e0 ec [2] fe f1 [2] fc f0 [2] e7 f6 [2] fb f1 [2] e7 de }

  condition:
    any of them
}