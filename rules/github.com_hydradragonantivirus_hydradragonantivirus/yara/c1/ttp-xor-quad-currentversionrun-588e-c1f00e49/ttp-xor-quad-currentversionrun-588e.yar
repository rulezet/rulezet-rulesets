rule TTP_XOR_QUAD_CurrentVersionRun_588e {
  strings:
    $key_588e = { 0b e1 [2] 2f ef [2] 04 c3 [2] 2a e1 [2] 3e fa [2] 31 e0 [2] 2f fd [2] 2d fc [2] 36 fa [2] 2a fd [2] 36 d2 }

  condition:
    any of them
}