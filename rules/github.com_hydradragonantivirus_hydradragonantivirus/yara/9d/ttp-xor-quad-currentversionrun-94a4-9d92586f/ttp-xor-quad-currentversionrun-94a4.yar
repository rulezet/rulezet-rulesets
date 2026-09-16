rule TTP_XOR_QUAD_CurrentVersionRun_94a4 {
  strings:
    $key_94a4 = { c7 cb [2] e3 c5 [2] c8 e9 [2] e6 cb [2] f2 d0 [2] fd ca [2] e3 d7 [2] e1 d6 [2] fa d0 [2] e6 d7 [2] fa f8 }

  condition:
    any of them
}