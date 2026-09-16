rule TTP_XOR_QUAD_CurrentVersionRun_899b {
  strings:
    $key_899b = { da f4 [2] fe fa [2] d5 d6 [2] fb f4 [2] ef ef [2] e0 f5 [2] fe e8 [2] fc e9 [2] e7 ef [2] fb e8 [2] e7 c7 }

  condition:
    any of them
}