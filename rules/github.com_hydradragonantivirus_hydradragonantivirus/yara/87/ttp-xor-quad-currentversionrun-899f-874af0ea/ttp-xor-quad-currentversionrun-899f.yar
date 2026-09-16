rule TTP_XOR_QUAD_CurrentVersionRun_899f {
  strings:
    $key_899f = { da f0 [2] fe fe [2] d5 d2 [2] fb f0 [2] ef eb [2] e0 f1 [2] fe ec [2] fc ed [2] e7 eb [2] fb ec [2] e7 c3 }

  condition:
    any of them
}