rule TTP_XOR_QUAD_CurrentVersionRun_4093 {
  strings:
    $key_4093 = { 13 fc [2] 37 f2 [2] 1c de [2] 32 fc [2] 26 e7 [2] 29 fd [2] 37 e0 [2] 35 e1 [2] 2e e7 [2] 32 e0 [2] 2e cf }

  condition:
    any of them
}