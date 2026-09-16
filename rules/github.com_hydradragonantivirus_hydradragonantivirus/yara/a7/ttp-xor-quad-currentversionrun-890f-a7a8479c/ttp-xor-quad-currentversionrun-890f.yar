rule TTP_XOR_QUAD_CurrentVersionRun_890f {
  strings:
    $key_890f = { da 60 [2] fe 6e [2] d5 42 [2] fb 60 [2] ef 7b [2] e0 61 [2] fe 7c [2] fc 7d [2] e7 7b [2] fb 7c [2] e7 53 }

  condition:
    any of them
}