rule TTP_XOR_QUAD_CurrentVersionRun_bb96 {
  strings:
    $key_bb96 = { e8 f9 [2] cc f7 [2] e7 db [2] c9 f9 [2] dd e2 [2] d2 f8 [2] cc e5 [2] ce e4 [2] d5 e2 [2] c9 e5 [2] d5 ca }

  condition:
    any of them
}