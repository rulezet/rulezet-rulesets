rule TTP_XOR_QUAD_CurrentVersionRun_5f93 {
  strings:
    $key_5f93 = { 0c fc [2] 28 f2 [2] 03 de [2] 2d fc [2] 39 e7 [2] 36 fd [2] 28 e0 [2] 2a e1 [2] 31 e7 [2] 2d e0 [2] 31 cf }

  condition:
    any of them
}