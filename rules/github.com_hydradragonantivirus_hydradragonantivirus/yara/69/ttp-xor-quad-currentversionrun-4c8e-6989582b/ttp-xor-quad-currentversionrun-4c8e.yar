rule TTP_XOR_QUAD_CurrentVersionRun_4c8e {
  strings:
    $key_4c8e = { 1f e1 [2] 3b ef [2] 10 c3 [2] 3e e1 [2] 2a fa [2] 25 e0 [2] 3b fd [2] 39 fc [2] 22 fa [2] 3e fd [2] 22 d2 }

  condition:
    any of them
}