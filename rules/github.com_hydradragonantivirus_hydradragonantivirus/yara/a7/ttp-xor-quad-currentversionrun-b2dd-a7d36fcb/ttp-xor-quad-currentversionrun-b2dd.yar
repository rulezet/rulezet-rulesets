rule TTP_XOR_QUAD_CurrentVersionRun_b2dd {
  strings:
    $key_b2dd = { e1 b2 [2] c5 bc [2] ee 90 [2] c0 b2 [2] d4 a9 [2] db b3 [2] c5 ae [2] c7 af [2] dc a9 [2] c0 ae [2] dc 81 }

  condition:
    any of them
}