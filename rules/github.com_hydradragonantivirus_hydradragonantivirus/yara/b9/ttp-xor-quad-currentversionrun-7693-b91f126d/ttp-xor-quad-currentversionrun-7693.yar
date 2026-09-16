rule TTP_XOR_QUAD_CurrentVersionRun_7693 {
  strings:
    $key_7693 = { 25 fc [2] 01 f2 [2] 2a de [2] 04 fc [2] 10 e7 [2] 1f fd [2] 01 e0 [2] 03 e1 [2] 18 e7 [2] 04 e0 [2] 18 cf }

  condition:
    any of them
}