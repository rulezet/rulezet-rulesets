rule TTP_XOR_QUAD_CurrentVersionRun_8e9f {
  strings:
    $key_8e9f = { dd f0 [2] f9 fe [2] d2 d2 [2] fc f0 [2] e8 eb [2] e7 f1 [2] f9 ec [2] fb ed [2] e0 eb [2] fc ec [2] e0 c3 }

  condition:
    any of them
}