rule TTP_XOR_QUAD_CurrentVersionRun_0093 {
  strings:
    $key_0093 = { 53 fc [2] 77 f2 [2] 5c de [2] 72 fc [2] 66 e7 [2] 69 fd [2] 77 e0 [2] 75 e1 [2] 6e e7 [2] 72 e0 [2] 6e cf }

  condition:
    any of them
}