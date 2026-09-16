rule TTP_XOR_QUAD_CurrentVersionRun_ea8e {
  strings:
    $key_ea8e = { b9 e1 [2] 9d ef [2] b6 c3 [2] 98 e1 [2] 8c fa [2] 83 e0 [2] 9d fd [2] 9f fc [2] 84 fa [2] 98 fd [2] 84 d2 }

  condition:
    any of them
}