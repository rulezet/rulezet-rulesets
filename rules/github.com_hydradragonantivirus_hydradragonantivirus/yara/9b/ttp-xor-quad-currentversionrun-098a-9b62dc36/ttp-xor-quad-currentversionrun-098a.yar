rule TTP_XOR_QUAD_CurrentVersionRun_098a {
  strings:
    $key_098a = { 5a e5 [2] 7e eb [2] 55 c7 [2] 7b e5 [2] 6f fe [2] 60 e4 [2] 7e f9 [2] 7c f8 [2] 67 fe [2] 7b f9 [2] 67 d6 }

  condition:
    any of them
}