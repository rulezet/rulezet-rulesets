rule TTP_XOR_QUAD_CurrentVersionRun_4193 {
  strings:
    $key_4193 = { 12 fc [2] 36 f2 [2] 1d de [2] 33 fc [2] 27 e7 [2] 28 fd [2] 36 e0 [2] 34 e1 [2] 2f e7 [2] 33 e0 [2] 2f cf }

  condition:
    any of them
}