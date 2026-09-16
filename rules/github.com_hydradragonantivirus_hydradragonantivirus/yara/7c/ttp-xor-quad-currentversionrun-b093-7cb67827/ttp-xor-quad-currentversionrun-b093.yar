rule TTP_XOR_QUAD_CurrentVersionRun_b093 {
  strings:
    $key_b093 = { e3 fc [2] c7 f2 [2] ec de [2] c2 fc [2] d6 e7 [2] d9 fd [2] c7 e0 [2] c5 e1 [2] de e7 [2] c2 e0 [2] de cf }

  condition:
    any of them
}