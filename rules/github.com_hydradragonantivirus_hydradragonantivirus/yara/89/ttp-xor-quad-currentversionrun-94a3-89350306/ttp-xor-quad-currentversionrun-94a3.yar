rule TTP_XOR_QUAD_CurrentVersionRun_94a3 {
  strings:
    $key_94a3 = { c7 cc [2] e3 c2 [2] c8 ee [2] e6 cc [2] f2 d7 [2] fd cd [2] e3 d0 [2] e1 d1 [2] fa d7 [2] e6 d0 [2] fa ff }

  condition:
    any of them
}