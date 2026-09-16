rule TTP_XOR_QUAD_CurrentVersionRun_8eae {
  strings:
    $key_8eae = { dd c1 [2] f9 cf [2] d2 e3 [2] fc c1 [2] e8 da [2] e7 c0 [2] f9 dd [2] fb dc [2] e0 da [2] fc dd [2] e0 f2 }

  condition:
    any of them
}