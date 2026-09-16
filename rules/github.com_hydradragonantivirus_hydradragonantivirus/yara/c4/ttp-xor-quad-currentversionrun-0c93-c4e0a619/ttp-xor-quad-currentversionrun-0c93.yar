rule TTP_XOR_QUAD_CurrentVersionRun_0c93 {
  strings:
    $key_0c93 = { 5f fc [2] 7b f2 [2] 50 de [2] 7e fc [2] 6a e7 [2] 65 fd [2] 7b e0 [2] 79 e1 [2] 62 e7 [2] 7e e0 [2] 62 cf }

  condition:
    any of them
}