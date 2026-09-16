rule TTP_XOR_QUAD_CurrentVersionRun_b38c {
  strings:
    $key_b38c = { e0 e3 [2] c4 ed [2] ef c1 [2] c1 e3 [2] d5 f8 [2] da e2 [2] c4 ff [2] c6 fe [2] dd f8 [2] c1 ff [2] dd d0 }

  condition:
    any of them
}