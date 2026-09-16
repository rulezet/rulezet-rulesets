rule TTP_XOR_QUAD_CurrentVersionRun_8be6 {
  strings:
    $key_8be6 = { d8 89 [2] fc 87 [2] d7 ab [2] f9 89 [2] ed 92 [2] e2 88 [2] fc 95 [2] fe 94 [2] e5 92 [2] f9 95 [2] e5 ba }

  condition:
    any of them
}