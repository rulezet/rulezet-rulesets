rule TTP_XOR_QUAD_CurrentVersionRun_3893 {
  strings:
    $key_3893 = { 6b fc [2] 4f f2 [2] 64 de [2] 4a fc [2] 5e e7 [2] 51 fd [2] 4f e0 [2] 4d e1 [2] 56 e7 [2] 4a e0 [2] 56 cf }

  condition:
    any of them
}