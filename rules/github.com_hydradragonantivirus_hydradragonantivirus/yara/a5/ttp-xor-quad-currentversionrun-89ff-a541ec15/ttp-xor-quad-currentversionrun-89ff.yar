rule TTP_XOR_QUAD_CurrentVersionRun_89ff {
  strings:
    $key_89ff = { da 90 [2] fe 9e [2] d5 b2 [2] fb 90 [2] ef 8b [2] e0 91 [2] fe 8c [2] fc 8d [2] e7 8b [2] fb 8c [2] e7 a3 }

  condition:
    any of them
}