rule TTP_XOR_QUAD_CurrentVersionRun_893f {
  strings:
    $key_893f = { da 50 [2] fe 5e [2] d5 72 [2] fb 50 [2] ef 4b [2] e0 51 [2] fe 4c [2] fc 4d [2] e7 4b [2] fb 4c [2] e7 63 }

  condition:
    any of them
}