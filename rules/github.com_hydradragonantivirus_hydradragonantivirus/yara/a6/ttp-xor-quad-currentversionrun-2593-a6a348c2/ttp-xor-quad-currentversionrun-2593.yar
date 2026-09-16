rule TTP_XOR_QUAD_CurrentVersionRun_2593 {
  strings:
    $key_2593 = { 76 fc [2] 52 f2 [2] 79 de [2] 57 fc [2] 43 e7 [2] 4c fd [2] 52 e0 [2] 50 e1 [2] 4b e7 [2] 57 e0 [2] 4b cf }

  condition:
    any of them
}