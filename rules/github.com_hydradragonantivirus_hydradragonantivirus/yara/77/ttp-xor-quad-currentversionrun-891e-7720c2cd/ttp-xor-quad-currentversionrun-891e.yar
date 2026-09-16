rule TTP_XOR_QUAD_CurrentVersionRun_891e {
  strings:
    $key_891e = { da 71 [2] fe 7f [2] d5 53 [2] fb 71 [2] ef 6a [2] e0 70 [2] fe 6d [2] fc 6c [2] e7 6a [2] fb 6d [2] e7 42 }

  condition:
    any of them
}