rule TTP_XOR_QUAD_CurrentVersionRun_8eaf {
  strings:
    $key_8eaf = { dd c0 [2] f9 ce [2] d2 e2 [2] fc c0 [2] e8 db [2] e7 c1 [2] f9 dc [2] fb dd [2] e0 db [2] fc dc [2] e0 f3 }

  condition:
    any of them
}