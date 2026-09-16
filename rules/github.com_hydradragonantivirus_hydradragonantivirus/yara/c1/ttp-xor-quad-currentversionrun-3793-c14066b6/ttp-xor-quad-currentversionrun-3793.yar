rule TTP_XOR_QUAD_CurrentVersionRun_3793 {
  strings:
    $key_3793 = { 64 fc [2] 40 f2 [2] 6b de [2] 45 fc [2] 51 e7 [2] 5e fd [2] 40 e0 [2] 42 e1 [2] 59 e7 [2] 45 e0 [2] 59 cf }

  condition:
    any of them
}