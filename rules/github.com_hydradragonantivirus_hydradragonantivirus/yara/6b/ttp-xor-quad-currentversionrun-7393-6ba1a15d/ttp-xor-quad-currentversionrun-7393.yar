rule TTP_XOR_QUAD_CurrentVersionRun_7393 {
  strings:
    $key_7393 = { 20 fc [2] 04 f2 [2] 2f de [2] 01 fc [2] 15 e7 [2] 1a fd [2] 04 e0 [2] 06 e1 [2] 1d e7 [2] 01 e0 [2] 1d cf }

  condition:
    any of them
}