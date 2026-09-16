rule TTP_XOR_QUAD_CurrentVersionRun_f98a {
  strings:
    $key_f98a = { aa e5 [2] 8e eb [2] a5 c7 [2] 8b e5 [2] 9f fe [2] 90 e4 [2] 8e f9 [2] 8c f8 [2] 97 fe [2] 8b f9 [2] 97 d6 }

  condition:
    any of them
}