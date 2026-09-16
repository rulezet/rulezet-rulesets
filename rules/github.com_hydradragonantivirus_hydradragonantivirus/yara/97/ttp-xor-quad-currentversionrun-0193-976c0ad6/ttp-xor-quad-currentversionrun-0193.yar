rule TTP_XOR_QUAD_CurrentVersionRun_0193 {
  strings:
    $key_0193 = { 52 fc [2] 76 f2 [2] 5d de [2] 73 fc [2] 67 e7 [2] 68 fd [2] 76 e0 [2] 74 e1 [2] 6f e7 [2] 73 e0 [2] 6f cf }

  condition:
    any of them
}