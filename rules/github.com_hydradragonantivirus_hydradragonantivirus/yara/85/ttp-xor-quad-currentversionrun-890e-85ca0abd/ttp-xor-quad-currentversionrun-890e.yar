rule TTP_XOR_QUAD_CurrentVersionRun_890e {
  strings:
    $key_890e = { da 61 [2] fe 6f [2] d5 43 [2] fb 61 [2] ef 7a [2] e0 60 [2] fe 7d [2] fc 7c [2] e7 7a [2] fb 7d [2] e7 52 }

  condition:
    any of them
}