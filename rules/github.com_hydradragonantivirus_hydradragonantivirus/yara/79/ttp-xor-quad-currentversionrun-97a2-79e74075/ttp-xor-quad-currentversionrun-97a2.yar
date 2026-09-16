rule TTP_XOR_QUAD_CurrentVersionRun_97a2 {
  strings:
    $key_97a2 = { c4 cd [2] e0 c3 [2] cb ef [2] e5 cd [2] f1 d6 [2] fe cc [2] e0 d1 [2] e2 d0 [2] f9 d6 [2] e5 d1 [2] f9 fe }

  condition:
    any of them
}