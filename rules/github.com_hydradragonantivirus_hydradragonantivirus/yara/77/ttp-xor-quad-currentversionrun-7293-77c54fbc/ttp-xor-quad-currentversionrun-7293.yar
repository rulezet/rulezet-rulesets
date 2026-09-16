rule TTP_XOR_QUAD_CurrentVersionRun_7293 {
  strings:
    $key_7293 = { 21 fc [2] 05 f2 [2] 2e de [2] 00 fc [2] 14 e7 [2] 1b fd [2] 05 e0 [2] 07 e1 [2] 1c e7 [2] 00 e0 [2] 1c cf }

  condition:
    any of them
}