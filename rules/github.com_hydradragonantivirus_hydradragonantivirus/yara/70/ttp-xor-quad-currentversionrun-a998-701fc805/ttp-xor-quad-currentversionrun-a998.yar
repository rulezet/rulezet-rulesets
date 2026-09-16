rule TTP_XOR_QUAD_CurrentVersionRun_a998 {
  strings:
    $key_a998 = { fa f7 [2] de f9 [2] f5 d5 [2] db f7 [2] cf ec [2] c0 f6 [2] de eb [2] dc ea [2] c7 ec [2] db eb [2] c7 c4 }

  condition:
    any of them
}