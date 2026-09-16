rule TTP_XOR_QUAD_CurrentVersionRun_a38c {
  strings:
    $key_a38c = { f0 e3 [2] d4 ed [2] ff c1 [2] d1 e3 [2] c5 f8 [2] ca e2 [2] d4 ff [2] d6 fe [2] cd f8 [2] d1 ff [2] cd d0 }

  condition:
    any of them
}