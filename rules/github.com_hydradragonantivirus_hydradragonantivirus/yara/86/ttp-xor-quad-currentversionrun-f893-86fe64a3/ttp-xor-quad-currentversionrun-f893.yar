rule TTP_XOR_QUAD_CurrentVersionRun_f893 {
  strings:
    $key_f893 = { ab fc [2] 8f f2 [2] a4 de [2] 8a fc [2] 9e e7 [2] 91 fd [2] 8f e0 [2] 8d e1 [2] 96 e7 [2] 8a e0 [2] 96 cf }

  condition:
    any of them
}