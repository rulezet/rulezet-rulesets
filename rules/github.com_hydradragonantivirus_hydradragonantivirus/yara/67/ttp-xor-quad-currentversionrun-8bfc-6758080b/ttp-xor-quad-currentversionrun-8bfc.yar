rule TTP_XOR_QUAD_CurrentVersionRun_8bfc {
  strings:
    $key_8bfc = { d8 93 [2] fc 9d [2] d7 b1 [2] f9 93 [2] ed 88 [2] e2 92 [2] fc 8f [2] fe 8e [2] e5 88 [2] f9 8f [2] e5 a0 }

  condition:
    any of them
}