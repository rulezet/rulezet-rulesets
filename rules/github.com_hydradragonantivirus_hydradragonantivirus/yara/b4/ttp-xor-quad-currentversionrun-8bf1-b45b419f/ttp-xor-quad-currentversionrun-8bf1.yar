rule TTP_XOR_QUAD_CurrentVersionRun_8bf1 {
  strings:
    $key_8bf1 = { d8 9e [2] fc 90 [2] d7 bc [2] f9 9e [2] ed 85 [2] e2 9f [2] fc 82 [2] fe 83 [2] e5 85 [2] f9 82 [2] e5 ad }

  condition:
    any of them
}