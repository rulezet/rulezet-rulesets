rule TTP_XOR_QUAD_CurrentVersionRun_4f93 {
  strings:
    $key_4f93 = { 1c fc [2] 38 f2 [2] 13 de [2] 3d fc [2] 29 e7 [2] 26 fd [2] 38 e0 [2] 3a e1 [2] 21 e7 [2] 3d e0 [2] 21 cf }

  condition:
    any of them
}