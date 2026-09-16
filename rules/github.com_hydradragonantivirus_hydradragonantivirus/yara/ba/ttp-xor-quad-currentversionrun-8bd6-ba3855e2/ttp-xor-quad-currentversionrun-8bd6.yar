rule TTP_XOR_QUAD_CurrentVersionRun_8bd6 {
  strings:
    $key_8bd6 = { d8 b9 [2] fc b7 [2] d7 9b [2] f9 b9 [2] ed a2 [2] e2 b8 [2] fc a5 [2] fe a4 [2] e5 a2 [2] f9 a5 [2] e5 8a }

  condition:
    any of them
}