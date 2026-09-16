rule TTP_XOR_QUAD_CurrentVersionRun_b393 {
  strings:
    $key_b393 = { e0 fc [2] c4 f2 [2] ef de [2] c1 fc [2] d5 e7 [2] da fd [2] c4 e0 [2] c6 e1 [2] dd e7 [2] c1 e0 [2] dd cf }

  condition:
    any of them
}