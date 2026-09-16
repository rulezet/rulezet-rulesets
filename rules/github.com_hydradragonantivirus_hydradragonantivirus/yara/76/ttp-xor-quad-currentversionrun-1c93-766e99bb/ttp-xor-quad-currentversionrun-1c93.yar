rule TTP_XOR_QUAD_CurrentVersionRun_1c93 {
  strings:
    $key_1c93 = { 4f fc [2] 6b f2 [2] 40 de [2] 6e fc [2] 7a e7 [2] 75 fd [2] 6b e0 [2] 69 e1 [2] 72 e7 [2] 6e e0 [2] 72 cf }

  condition:
    any of them
}