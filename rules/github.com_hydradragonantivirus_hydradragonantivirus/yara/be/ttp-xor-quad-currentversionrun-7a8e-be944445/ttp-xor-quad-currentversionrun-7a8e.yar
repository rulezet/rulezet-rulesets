rule TTP_XOR_QUAD_CurrentVersionRun_7a8e {
  strings:
    $key_7a8e = { 29 e1 [2] 0d ef [2] 26 c3 [2] 08 e1 [2] 1c fa [2] 13 e0 [2] 0d fd [2] 0f fc [2] 14 fa [2] 08 fd [2] 14 d2 }

  condition:
    any of them
}