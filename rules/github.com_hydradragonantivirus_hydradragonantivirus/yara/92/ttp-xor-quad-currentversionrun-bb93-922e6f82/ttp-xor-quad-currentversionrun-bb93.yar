rule TTP_XOR_QUAD_CurrentVersionRun_bb93 {
  strings:
    $key_bb93 = { e8 fc [2] cc f2 [2] e7 de [2] c9 fc [2] dd e7 [2] d2 fd [2] cc e0 [2] ce e1 [2] d5 e7 [2] c9 e0 [2] d5 cf }

  condition:
    any of them
}