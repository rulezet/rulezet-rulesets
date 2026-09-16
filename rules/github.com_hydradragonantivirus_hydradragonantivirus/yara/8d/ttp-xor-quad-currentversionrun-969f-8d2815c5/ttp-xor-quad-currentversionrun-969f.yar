rule TTP_XOR_QUAD_CurrentVersionRun_969f {
  strings:
    $key_969f = { c5 f0 [2] e1 fe [2] ca d2 [2] e4 f0 [2] f0 eb [2] ff f1 [2] e1 ec [2] e3 ed [2] f8 eb [2] e4 ec [2] f8 c3 }

  condition:
    any of them
}