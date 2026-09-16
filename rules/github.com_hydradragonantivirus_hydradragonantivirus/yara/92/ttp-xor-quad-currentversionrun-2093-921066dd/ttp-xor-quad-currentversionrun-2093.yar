rule TTP_XOR_QUAD_CurrentVersionRun_2093 {
  strings:
    $key_2093 = { 73 fc [2] 57 f2 [2] 7c de [2] 52 fc [2] 46 e7 [2] 49 fd [2] 57 e0 [2] 55 e1 [2] 4e e7 [2] 52 e0 [2] 4e cf }

  condition:
    any of them
}