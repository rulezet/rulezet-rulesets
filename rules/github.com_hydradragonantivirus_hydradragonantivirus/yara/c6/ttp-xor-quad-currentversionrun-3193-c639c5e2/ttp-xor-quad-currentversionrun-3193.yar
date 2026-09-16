rule TTP_XOR_QUAD_CurrentVersionRun_3193 {
  strings:
    $key_3193 = { 62 fc [2] 46 f2 [2] 6d de [2] 43 fc [2] 57 e7 [2] 58 fd [2] 46 e0 [2] 44 e1 [2] 5f e7 [2] 43 e0 [2] 5f cf }

  condition:
    any of them
}