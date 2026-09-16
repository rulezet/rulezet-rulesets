rule TTP_XOR_QUAD_CurrentVersionRun_b2da {
  strings:
    $key_b2da = { e1 b5 [2] c5 bb [2] ee 97 [2] c0 b5 [2] d4 ae [2] db b4 [2] c5 a9 [2] c7 a8 [2] dc ae [2] c0 a9 [2] dc 86 }

  condition:
    any of them
}