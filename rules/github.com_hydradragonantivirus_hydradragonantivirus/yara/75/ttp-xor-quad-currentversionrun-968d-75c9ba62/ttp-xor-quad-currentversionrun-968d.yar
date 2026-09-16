rule TTP_XOR_QUAD_CurrentVersionRun_968d {
  strings:
    $key_968d = { c5 e2 [2] e1 ec [2] ca c0 [2] e4 e2 [2] f0 f9 [2] ff e3 [2] e1 fe [2] e3 ff [2] f8 f9 [2] e4 fe [2] f8 d1 }

  condition:
    any of them
}