rule TTP_XOR_QUAD_CurrentVersionRun_d88e {
  strings:
    $key_d88e = { 8b e1 [2] af ef [2] 84 c3 [2] aa e1 [2] be fa [2] b1 e0 [2] af fd [2] ad fc [2] b6 fa [2] aa fd [2] b6 d2 }

  condition:
    any of them
}