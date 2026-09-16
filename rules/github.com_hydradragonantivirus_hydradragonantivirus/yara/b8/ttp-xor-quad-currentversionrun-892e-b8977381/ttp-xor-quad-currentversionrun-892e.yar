rule TTP_XOR_QUAD_CurrentVersionRun_892e {
  strings:
    $key_892e = { da 41 [2] fe 4f [2] d5 63 [2] fb 41 [2] ef 5a [2] e0 40 [2] fe 5d [2] fc 5c [2] e7 5a [2] fb 5d [2] e7 72 }

  condition:
    any of them
}