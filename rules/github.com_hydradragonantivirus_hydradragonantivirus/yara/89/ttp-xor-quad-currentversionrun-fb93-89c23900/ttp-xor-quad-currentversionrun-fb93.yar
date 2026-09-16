rule TTP_XOR_QUAD_CurrentVersionRun_fb93 {
  strings:
    $key_fb93 = { a8 fc [2] 8c f2 [2] a7 de [2] 89 fc [2] 9d e7 [2] 92 fd [2] 8c e0 [2] 8e e1 [2] 95 e7 [2] 89 e0 [2] 95 cf }

  condition:
    any of them
}