rule TTP_XOR_QUAD_CurrentVersionRun_8f93 {
  strings:
    $key_8f93 = { dc fc [2] f8 f2 [2] d3 de [2] fd fc [2] e9 e7 [2] e6 fd [2] f8 e0 [2] fa e1 [2] e1 e7 [2] fd e0 [2] e1 cf }

  condition:
    any of them
}