rule TTP_XOR_QUAD_CurrentVersionRun_3093 {
  strings:
    $key_3093 = { 63 fc [2] 47 f2 [2] 6c de [2] 42 fc [2] 56 e7 [2] 59 fd [2] 47 e0 [2] 45 e1 [2] 5e e7 [2] 42 e0 [2] 5e cf }

  condition:
    any of them
}