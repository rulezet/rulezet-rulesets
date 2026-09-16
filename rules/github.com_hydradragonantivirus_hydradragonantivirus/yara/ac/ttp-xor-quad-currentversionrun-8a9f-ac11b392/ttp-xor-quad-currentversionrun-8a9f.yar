rule TTP_XOR_QUAD_CurrentVersionRun_8a9f {
  strings:
    $key_8a9f = { d9 f0 [2] fd fe [2] d6 d2 [2] f8 f0 [2] ec eb [2] e3 f1 [2] fd ec [2] ff ed [2] e4 eb [2] f8 ec [2] e4 c3 }

  condition:
    any of them
}