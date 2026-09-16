rule TTP_XOR_QUAD_CurrentVersionRun_b29f {
  strings:
    $key_b29f = { e1 f0 [2] c5 fe [2] ee d2 [2] c0 f0 [2] d4 eb [2] db f1 [2] c5 ec [2] c7 ed [2] dc eb [2] c0 ec [2] dc c3 }

  condition:
    any of them
}