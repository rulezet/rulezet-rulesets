rule TTP_XOR_QUAD_CurrentVersionRun_1293 {
  strings:
    $key_1293 = { 41 fc [2] 65 f2 [2] 4e de [2] 60 fc [2] 74 e7 [2] 7b fd [2] 65 e0 [2] 67 e1 [2] 7c e7 [2] 60 e0 [2] 7c cf }

  condition:
    any of them
}