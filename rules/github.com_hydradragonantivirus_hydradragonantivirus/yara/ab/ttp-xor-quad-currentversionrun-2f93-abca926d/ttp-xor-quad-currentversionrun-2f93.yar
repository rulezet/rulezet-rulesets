rule TTP_XOR_QUAD_CurrentVersionRun_2f93 {
  strings:
    $key_2f93 = { 7c fc [2] 58 f2 [2] 73 de [2] 5d fc [2] 49 e7 [2] 46 fd [2] 58 e0 [2] 5a e1 [2] 41 e7 [2] 5d e0 [2] 41 cf }

  condition:
    any of them
}