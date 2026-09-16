rule TTP_XOR_QUAD_CurrentVersionRun_3593 {
  strings:
    $key_3593 = { 66 fc [2] 42 f2 [2] 69 de [2] 47 fc [2] 53 e7 [2] 5c fd [2] 42 e0 [2] 40 e1 [2] 5b e7 [2] 47 e0 [2] 5b cf }

  condition:
    any of them
}