rule TTP_XOR_QUAD_CurrentVersionRun_6493 {
  strings:
    $key_6493 = { 37 fc [2] 13 f2 [2] 38 de [2] 16 fc [2] 02 e7 [2] 0d fd [2] 13 e0 [2] 11 e1 [2] 0a e7 [2] 16 e0 [2] 0a cf }

  condition:
    any of them
}