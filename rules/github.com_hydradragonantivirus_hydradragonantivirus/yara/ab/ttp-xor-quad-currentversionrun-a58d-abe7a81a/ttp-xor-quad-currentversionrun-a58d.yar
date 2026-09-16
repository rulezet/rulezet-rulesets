rule TTP_XOR_QUAD_CurrentVersionRun_a58d {
  strings:
    $key_a58d = { f6 e2 [2] d2 ec [2] f9 c0 [2] d7 e2 [2] c3 f9 [2] cc e3 [2] d2 fe [2] d0 ff [2] cb f9 [2] d7 fe [2] cb d1 }

  condition:
    any of them
}