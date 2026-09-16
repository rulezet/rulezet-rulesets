rule TTP_XOR_QUAD_CurrentVersionRun_1193 {
  strings:
    $key_1193 = { 42 fc [2] 66 f2 [2] 4d de [2] 63 fc [2] 77 e7 [2] 78 fd [2] 66 e0 [2] 64 e1 [2] 7f e7 [2] 63 e0 [2] 7f cf }

  condition:
    any of them
}