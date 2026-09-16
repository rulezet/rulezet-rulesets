rule TTP_XOR_QUAD_CurrentVersionRun_8929 {
  strings:
    $key_8929 = { da 46 [2] fe 48 [2] d5 64 [2] fb 46 [2] ef 5d [2] e0 47 [2] fe 5a [2] fc 5b [2] e7 5d [2] fb 5a [2] e7 75 }

  condition:
    any of them
}