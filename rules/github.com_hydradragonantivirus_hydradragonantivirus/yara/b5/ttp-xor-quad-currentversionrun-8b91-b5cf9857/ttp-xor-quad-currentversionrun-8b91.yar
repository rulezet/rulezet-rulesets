rule TTP_XOR_QUAD_CurrentVersionRun_8b91 {
  strings:
    $key_8b91 = { d8 fe [2] fc f0 [2] d7 dc [2] f9 fe [2] ed e5 [2] e2 ff [2] fc e2 [2] fe e3 [2] e5 e5 [2] f9 e2 [2] e5 cd }

  condition:
    any of them
}