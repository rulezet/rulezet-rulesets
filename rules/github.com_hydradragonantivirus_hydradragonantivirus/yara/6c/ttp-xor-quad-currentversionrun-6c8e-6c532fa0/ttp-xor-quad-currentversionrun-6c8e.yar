rule TTP_XOR_QUAD_CurrentVersionRun_6c8e {
  strings:
    $key_6c8e = { 3f e1 [2] 1b ef [2] 30 c3 [2] 1e e1 [2] 0a fa [2] 05 e0 [2] 1b fd [2] 19 fc [2] 02 fa [2] 1e fd [2] 02 d2 }

  condition:
    any of them
}