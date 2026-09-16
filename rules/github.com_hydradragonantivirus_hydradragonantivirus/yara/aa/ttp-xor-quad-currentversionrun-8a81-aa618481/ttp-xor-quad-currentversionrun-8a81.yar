rule TTP_XOR_QUAD_CurrentVersionRun_8a81 {
  strings:
    $key_8a81 = { d9 ee [2] fd e0 [2] d6 cc [2] f8 ee [2] ec f5 [2] e3 ef [2] fd f2 [2] ff f3 [2] e4 f5 [2] f8 f2 [2] e4 dd }

  condition:
    any of them
}