rule TTP_XOR_QUAD_CurrentVersionRun_f88e {
  strings:
    $key_f88e = { ab e1 [2] 8f ef [2] a4 c3 [2] 8a e1 [2] 9e fa [2] 91 e0 [2] 8f fd [2] 8d fc [2] 96 fa [2] 8a fd [2] 96 d2 }

  condition:
    any of them
}