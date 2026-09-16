rule TTP_XOR_QUAD_CurrentVersionRun_8912 {
  strings:
    $key_8912 = { da 7d [2] fe 73 [2] d5 5f [2] fb 7d [2] ef 66 [2] e0 7c [2] fe 61 [2] fc 60 [2] e7 66 [2] fb 61 [2] e7 4e }

  condition:
    any of them
}