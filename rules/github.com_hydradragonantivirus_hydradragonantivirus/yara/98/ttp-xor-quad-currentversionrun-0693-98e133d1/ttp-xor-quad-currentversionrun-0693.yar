rule TTP_XOR_QUAD_CurrentVersionRun_0693 {
  strings:
    $key_0693 = { 55 fc [2] 71 f2 [2] 5a de [2] 74 fc [2] 60 e7 [2] 6f fd [2] 71 e0 [2] 73 e1 [2] 68 e7 [2] 74 e0 [2] 68 cf }

  condition:
    any of them
}