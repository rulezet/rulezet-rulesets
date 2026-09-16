rule TTP_XOR_QUAD_CurrentVersionRun_7f93 {
  strings:
    $key_7f93 = { 2c fc [2] 08 f2 [2] 23 de [2] 0d fc [2] 19 e7 [2] 16 fd [2] 08 e0 [2] 0a e1 [2] 11 e7 [2] 0d e0 [2] 11 cf }

  condition:
    any of them
}