rule TTP_XOR_QUAD_CurrentVersionRun_4693 {
  strings:
    $key_4693 = { 15 fc [2] 31 f2 [2] 1a de [2] 34 fc [2] 20 e7 [2] 2f fd [2] 31 e0 [2] 33 e1 [2] 28 e7 [2] 34 e0 [2] 28 cf }

  condition:
    any of them
}