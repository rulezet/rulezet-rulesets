rule TTP_XOR_QUAD_CurrentVersionRun_8be0 {
  strings:
    $key_8be0 = { d8 8f [2] fc 81 [2] d7 ad [2] f9 8f [2] ed 94 [2] e2 8e [2] fc 93 [2] fe 92 [2] e5 94 [2] f9 93 [2] e5 bc }

  condition:
    any of them
}