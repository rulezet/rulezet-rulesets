rule TTP_XOR_QUAD_CurrentVersionRun_3693 {
  strings:
    $key_3693 = { 65 fc [2] 41 f2 [2] 6a de [2] 44 fc [2] 50 e7 [2] 5f fd [2] 41 e0 [2] 43 e1 [2] 58 e7 [2] 44 e0 [2] 58 cf }

  condition:
    any of them
}