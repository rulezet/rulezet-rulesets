rule TTP_XOR_QUAD_CurrentVersionRun_d98e {
  strings:
    $key_d98e = { 8a e1 [2] ae ef [2] 85 c3 [2] ab e1 [2] bf fa [2] b0 e0 [2] ae fd [2] ac fc [2] b7 fa [2] ab fd [2] b7 d2 }

  condition:
    any of them
}