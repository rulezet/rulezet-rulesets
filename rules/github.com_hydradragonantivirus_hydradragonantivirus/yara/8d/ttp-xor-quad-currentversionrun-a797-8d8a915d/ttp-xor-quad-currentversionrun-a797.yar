rule TTP_XOR_QUAD_CurrentVersionRun_a797 {
  strings:
    $key_a797 = { f4 f8 [2] d0 f6 [2] fb da [2] d5 f8 [2] c1 e3 [2] ce f9 [2] d0 e4 [2] d2 e5 [2] c9 e3 [2] d5 e4 [2] c9 cb }

  condition:
    any of them
}