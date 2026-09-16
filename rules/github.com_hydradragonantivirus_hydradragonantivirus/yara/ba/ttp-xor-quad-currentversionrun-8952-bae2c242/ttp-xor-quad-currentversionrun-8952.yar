rule TTP_XOR_QUAD_CurrentVersionRun_8952 {
  strings:
    $key_8952 = { da 3d [2] fe 33 [2] d5 1f [2] fb 3d [2] ef 26 [2] e0 3c [2] fe 21 [2] fc 20 [2] e7 26 [2] fb 21 [2] e7 0e }

  condition:
    any of them
}