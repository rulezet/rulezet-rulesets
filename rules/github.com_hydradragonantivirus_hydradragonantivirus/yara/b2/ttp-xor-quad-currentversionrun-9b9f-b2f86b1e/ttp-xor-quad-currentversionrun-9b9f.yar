rule TTP_XOR_QUAD_CurrentVersionRun_9b9f {
  strings:
    $key_9b9f = { c8 f0 [2] ec fe [2] c7 d2 [2] e9 f0 [2] fd eb [2] f2 f1 [2] ec ec [2] ee ed [2] f5 eb [2] e9 ec [2] f5 c3 }

  condition:
    any of them
}