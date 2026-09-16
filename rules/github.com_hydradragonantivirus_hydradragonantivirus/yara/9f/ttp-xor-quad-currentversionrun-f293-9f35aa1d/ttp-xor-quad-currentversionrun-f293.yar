rule TTP_XOR_QUAD_CurrentVersionRun_f293 {
  strings:
    $key_f293 = { a1 fc [2] 85 f2 [2] ae de [2] 80 fc [2] 94 e7 [2] 9b fd [2] 85 e0 [2] 87 e1 [2] 9c e7 [2] 80 e0 [2] 9c cf }

  condition:
    any of them
}