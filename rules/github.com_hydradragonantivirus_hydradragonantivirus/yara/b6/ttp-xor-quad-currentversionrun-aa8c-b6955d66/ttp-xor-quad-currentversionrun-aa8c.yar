rule TTP_XOR_QUAD_CurrentVersionRun_aa8c {
  strings:
    $key_aa8c = { f9 e3 [2] dd ed [2] f6 c1 [2] d8 e3 [2] cc f8 [2] c3 e2 [2] dd ff [2] df fe [2] c4 f8 [2] d8 ff [2] c4 d0 }

  condition:
    any of them
}