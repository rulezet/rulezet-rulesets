rule TTP_XOR_QUAD_CurrentVersionRun_8bf4 {
  strings:
    $key_8bf4 = { d8 9b [2] fc 95 [2] d7 b9 [2] f9 9b [2] ed 80 [2] e2 9a [2] fc 87 [2] fe 86 [2] e5 80 [2] f9 87 [2] e5 a8 }

  condition:
    any of them
}