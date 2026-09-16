rule TTP_XOR_QUAD_CurrentVersionRun_8b81 {
  strings:
    $key_8b81 = { d8 ee [2] fc e0 [2] d7 cc [2] f9 ee [2] ed f5 [2] e2 ef [2] fc f2 [2] fe f3 [2] e5 f5 [2] f9 f2 [2] e5 dd }

  condition:
    any of them
}