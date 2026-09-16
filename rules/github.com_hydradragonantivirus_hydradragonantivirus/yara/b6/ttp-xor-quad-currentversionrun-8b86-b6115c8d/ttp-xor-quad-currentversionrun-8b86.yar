rule TTP_XOR_QUAD_CurrentVersionRun_8b86 {
  strings:
    $key_8b86 = { d8 e9 [2] fc e7 [2] d7 cb [2] f9 e9 [2] ed f2 [2] e2 e8 [2] fc f5 [2] fe f4 [2] e5 f2 [2] f9 f5 [2] e5 da }

  condition:
    any of them
}