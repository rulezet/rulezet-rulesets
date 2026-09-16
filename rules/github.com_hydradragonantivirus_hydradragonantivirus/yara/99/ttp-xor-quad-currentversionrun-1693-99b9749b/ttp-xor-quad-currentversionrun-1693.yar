rule TTP_XOR_QUAD_CurrentVersionRun_1693 {
  strings:
    $key_1693 = { 45 fc [2] 61 f2 [2] 4a de [2] 64 fc [2] 70 e7 [2] 7f fd [2] 61 e0 [2] 63 e1 [2] 78 e7 [2] 64 e0 [2] 78 cf }

  condition:
    any of them
}