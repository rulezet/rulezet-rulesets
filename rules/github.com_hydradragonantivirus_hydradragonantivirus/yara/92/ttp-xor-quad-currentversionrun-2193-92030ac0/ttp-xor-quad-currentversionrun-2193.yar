rule TTP_XOR_QUAD_CurrentVersionRun_2193 {
  strings:
    $key_2193 = { 72 fc [2] 56 f2 [2] 7d de [2] 53 fc [2] 47 e7 [2] 48 fd [2] 56 e0 [2] 54 e1 [2] 4f e7 [2] 53 e0 [2] 4f cf }

  condition:
    any of them
}