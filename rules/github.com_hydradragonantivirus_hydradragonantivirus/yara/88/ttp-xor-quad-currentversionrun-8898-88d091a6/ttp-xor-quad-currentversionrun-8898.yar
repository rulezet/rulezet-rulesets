rule TTP_XOR_QUAD_CurrentVersionRun_8898 {
  strings:
    $key_8898 = { db f7 [2] ff f9 [2] d4 d5 [2] fa f7 [2] ee ec [2] e1 f6 [2] ff eb [2] fd ea [2] e6 ec [2] fa eb [2] e6 c4 }

  condition:
    any of them
}