rule TTP_XOR_QUAD_CurrentVersionRun_8bf8 {
  strings:
    $key_8bf8 = { d8 97 [2] fc 99 [2] d7 b5 [2] f9 97 [2] ed 8c [2] e2 96 [2] fc 8b [2] fe 8a [2] e5 8c [2] f9 8b [2] e5 a4 }

  condition:
    any of them
}