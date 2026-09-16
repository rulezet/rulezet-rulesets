rule TTP_XOR_QUAD_CurrentVersionRun_259b {
  strings:
    $key_259b = { 76 f4 [2] 52 fa [2] 79 d6 [2] 57 f4 [2] 43 ef [2] 4c f5 [2] 52 e8 [2] 50 e9 [2] 4b ef [2] 57 e8 [2] 4b c7 }

  condition:
    any of them
}