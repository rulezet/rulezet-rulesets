rule TTP_XOR_QUAD_CurrentVersionRun_978d {
  strings:
    $key_978d = { c4 e2 [2] e0 ec [2] cb c0 [2] e5 e2 [2] f1 f9 [2] fe e3 [2] e0 fe [2] e2 ff [2] f9 f9 [2] e5 fe [2] f9 d1 }

  condition:
    any of them
}