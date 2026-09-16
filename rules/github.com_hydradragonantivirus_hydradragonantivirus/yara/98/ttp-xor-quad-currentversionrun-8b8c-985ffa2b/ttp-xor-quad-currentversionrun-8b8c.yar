rule TTP_XOR_QUAD_CurrentVersionRun_8b8c {
  strings:
    $key_8b8c = { d8 e3 [2] fc ed [2] d7 c1 [2] f9 e3 [2] ed f8 [2] e2 e2 [2] fc ff [2] fe fe [2] e5 f8 [2] f9 ff [2] e5 d0 }

  condition:
    any of them
}