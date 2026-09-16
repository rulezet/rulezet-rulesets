rule TTP_XOR_QUAD_CurrentVersionRun_288e {
  strings:
    $key_288e = { 7b e1 [2] 5f ef [2] 74 c3 [2] 5a e1 [2] 4e fa [2] 41 e0 [2] 5f fd [2] 5d fc [2] 46 fa [2] 5a fd [2] 46 d2 }

  condition:
    any of them
}