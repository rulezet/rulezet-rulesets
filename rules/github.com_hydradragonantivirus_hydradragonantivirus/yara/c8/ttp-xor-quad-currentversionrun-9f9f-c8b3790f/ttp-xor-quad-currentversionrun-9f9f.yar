rule TTP_XOR_QUAD_CurrentVersionRun_9f9f {
  strings:
    $key_9f9f = { cc f0 [2] e8 fe [2] c3 d2 [2] ed f0 [2] f9 eb [2] f6 f1 [2] e8 ec [2] ea ed [2] f1 eb [2] ed ec [2] f1 c3 }

  condition:
    any of them
}