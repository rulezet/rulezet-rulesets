rule TTP_XOR_QUAD_CurrentVersionRun_0d93 {
  strings:
    $key_0d93 = { 5e fc [2] 7a f2 [2] 51 de [2] 7f fc [2] 6b e7 [2] 64 fd [2] 7a e0 [2] 78 e1 [2] 63 e7 [2] 7f e0 [2] 63 cf }

  condition:
    any of them
}