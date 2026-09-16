rule TTP_XOR_QUAD_CurrentVersionRun_1593 {
  strings:
    $key_1593 = { 46 fc [2] 62 f2 [2] 49 de [2] 67 fc [2] 73 e7 [2] 7c fd [2] 62 e0 [2] 60 e1 [2] 7b e7 [2] 67 e0 [2] 7b cf }

  condition:
    any of them
}