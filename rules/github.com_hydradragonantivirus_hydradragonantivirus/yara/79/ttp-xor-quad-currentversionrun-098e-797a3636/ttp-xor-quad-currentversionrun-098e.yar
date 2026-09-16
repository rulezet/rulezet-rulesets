rule TTP_XOR_QUAD_CurrentVersionRun_098e {
  strings:
    $key_098e = { 5a e1 [2] 7e ef [2] 55 c3 [2] 7b e1 [2] 6f fa [2] 60 e0 [2] 7e fd [2] 7c fc [2] 67 fa [2] 7b fd [2] 67 d2 }

  condition:
    any of them
}