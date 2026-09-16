rule TTP_XOR_QUAD_CurrentVersionRun_8bd3 {
  strings:
    $key_8bd3 = { d8 bc [2] fc b2 [2] d7 9e [2] f9 bc [2] ed a7 [2] e2 bd [2] fc a0 [2] fe a1 [2] e5 a7 [2] f9 a0 [2] e5 8f }

  condition:
    any of them
}