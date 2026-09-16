rule TTP_XOR_QUAD_CurrentVersionRun_3c8e {
  strings:
    $key_3c8e = { 6f e1 [2] 4b ef [2] 60 c3 [2] 4e e1 [2] 5a fa [2] 55 e0 [2] 4b fd [2] 49 fc [2] 52 fa [2] 4e fd [2] 52 d2 }

  condition:
    any of them
}