rule TTP_XOR_QUAD_CurrentVersionRun_3293 {
  strings:
    $key_3293 = { 61 fc [2] 45 f2 [2] 6e de [2] 40 fc [2] 54 e7 [2] 5b fd [2] 45 e0 [2] 47 e1 [2] 5c e7 [2] 40 e0 [2] 5c cf }

  condition:
    any of them
}