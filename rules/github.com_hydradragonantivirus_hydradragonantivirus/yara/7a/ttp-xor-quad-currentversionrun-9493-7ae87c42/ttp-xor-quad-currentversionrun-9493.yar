rule TTP_XOR_QUAD_CurrentVersionRun_9493 {
  strings:
    $key_9493 = { c7 fc [2] e3 f2 [2] c8 de [2] e6 fc [2] f2 e7 [2] fd fd [2] e3 e0 [2] e1 e1 [2] fa e7 [2] e6 e0 [2] fa cf }

  condition:
    any of them
}