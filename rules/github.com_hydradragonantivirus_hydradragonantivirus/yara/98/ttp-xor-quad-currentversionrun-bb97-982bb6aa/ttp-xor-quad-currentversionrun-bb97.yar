rule TTP_XOR_QUAD_CurrentVersionRun_bb97 {
  strings:
    $key_bb97 = { e8 f8 [2] cc f6 [2] e7 da [2] c9 f8 [2] dd e3 [2] d2 f9 [2] cc e4 [2] ce e5 [2] d5 e3 [2] c9 e4 [2] d5 cb }

  condition:
    any of them
}