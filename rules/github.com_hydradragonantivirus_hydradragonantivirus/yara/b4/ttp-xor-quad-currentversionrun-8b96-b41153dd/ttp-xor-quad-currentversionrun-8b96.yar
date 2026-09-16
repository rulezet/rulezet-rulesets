rule TTP_XOR_QUAD_CurrentVersionRun_8b96 {
  strings:
    $key_8b96 = { d8 f9 [2] fc f7 [2] d7 db [2] f9 f9 [2] ed e2 [2] e2 f8 [2] fc e5 [2] fe e4 [2] e5 e2 [2] f9 e5 [2] e5 ca }

  condition:
    any of them
}