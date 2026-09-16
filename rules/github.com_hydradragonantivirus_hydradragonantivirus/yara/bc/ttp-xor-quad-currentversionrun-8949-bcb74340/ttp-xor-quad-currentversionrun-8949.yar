rule TTP_XOR_QUAD_CurrentVersionRun_8949 {
  strings:
    $key_8949 = { da 26 [2] fe 28 [2] d5 04 [2] fb 26 [2] ef 3d [2] e0 27 [2] fe 3a [2] fc 3b [2] e7 3d [2] fb 3a [2] e7 15 }

  condition:
    any of them
}