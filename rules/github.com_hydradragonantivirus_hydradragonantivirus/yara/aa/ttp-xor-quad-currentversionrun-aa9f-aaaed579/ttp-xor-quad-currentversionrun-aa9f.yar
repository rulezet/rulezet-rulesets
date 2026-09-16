rule TTP_XOR_QUAD_CurrentVersionRun_aa9f {
  strings:
    $key_aa9f = { f9 f0 [2] dd fe [2] f6 d2 [2] d8 f0 [2] cc eb [2] c3 f1 [2] dd ec [2] df ed [2] c4 eb [2] d8 ec [2] c4 c3 }

  condition:
    any of them
}