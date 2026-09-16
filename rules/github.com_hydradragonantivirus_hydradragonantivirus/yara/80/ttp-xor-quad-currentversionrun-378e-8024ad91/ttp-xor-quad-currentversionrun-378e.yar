rule TTP_XOR_QUAD_CurrentVersionRun_378e {
  strings:
    $key_378e = { 64 e1 [2] 40 ef [2] 6b c3 [2] 45 e1 [2] 51 fa [2] 5e e0 [2] 40 fd [2] 42 fc [2] 59 fa [2] 45 fd [2] 59 d2 }

  condition:
    any of them
}