rule TTP_XOR_QUAD_CurrentVersionRun_8e8c {
  strings:
    $key_8e8c = { dd e3 [2] f9 ed [2] d2 c1 [2] fc e3 [2] e8 f8 [2] e7 e2 [2] f9 ff [2] fb fe [2] e0 f8 [2] fc ff [2] e0 d0 }

  condition:
    any of them
}