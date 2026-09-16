rule TTP_XOR_QUAD_CurrentVersionRun_7093 {
  strings:
    $key_7093 = { 23 fc [2] 07 f2 [2] 2c de [2] 02 fc [2] 16 e7 [2] 19 fd [2] 07 e0 [2] 05 e1 [2] 1e e7 [2] 02 e0 [2] 1e cf }

  condition:
    any of them
}