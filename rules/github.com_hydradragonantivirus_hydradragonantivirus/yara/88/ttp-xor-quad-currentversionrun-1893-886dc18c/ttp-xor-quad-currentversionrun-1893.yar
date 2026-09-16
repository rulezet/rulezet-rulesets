rule TTP_XOR_QUAD_CurrentVersionRun_1893 {
  strings:
    $key_1893 = { 4b fc [2] 6f f2 [2] 44 de [2] 6a fc [2] 7e e7 [2] 71 fd [2] 6f e0 [2] 6d e1 [2] 76 e7 [2] 6a e0 [2] 76 cf }

  condition:
    any of them
}