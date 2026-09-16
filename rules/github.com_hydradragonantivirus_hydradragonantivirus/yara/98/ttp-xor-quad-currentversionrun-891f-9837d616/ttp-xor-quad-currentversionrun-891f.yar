rule TTP_XOR_QUAD_CurrentVersionRun_891f {
  strings:
    $key_891f = { da 70 [2] fe 7e [2] d5 52 [2] fb 70 [2] ef 6b [2] e0 71 [2] fe 6c [2] fc 6d [2] e7 6b [2] fb 6c [2] e7 43 }

  condition:
    any of them
}