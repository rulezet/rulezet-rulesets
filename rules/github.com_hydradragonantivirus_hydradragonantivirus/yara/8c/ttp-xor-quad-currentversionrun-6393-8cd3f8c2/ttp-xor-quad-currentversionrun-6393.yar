rule TTP_XOR_QUAD_CurrentVersionRun_6393 {
  strings:
    $key_6393 = { 30 fc [2] 14 f2 [2] 3f de [2] 11 fc [2] 05 e7 [2] 0a fd [2] 14 e0 [2] 16 e1 [2] 0d e7 [2] 11 e0 [2] 0d cf }

  condition:
    any of them
}