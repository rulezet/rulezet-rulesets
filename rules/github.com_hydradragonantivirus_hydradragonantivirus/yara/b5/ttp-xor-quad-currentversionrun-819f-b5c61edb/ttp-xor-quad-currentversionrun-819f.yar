rule TTP_XOR_QUAD_CurrentVersionRun_819f {
  strings:
    $key_819f = { d2 f0 [2] f6 fe [2] dd d2 [2] f3 f0 [2] e7 eb [2] e8 f1 [2] f6 ec [2] f4 ed [2] ef eb [2] f3 ec [2] ef c3 }

  condition:
    any of them
}