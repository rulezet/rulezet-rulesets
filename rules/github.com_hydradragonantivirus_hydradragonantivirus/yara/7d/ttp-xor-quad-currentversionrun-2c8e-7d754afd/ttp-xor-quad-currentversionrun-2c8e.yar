rule TTP_XOR_QUAD_CurrentVersionRun_2c8e {
  strings:
    $key_2c8e = { 7f e1 [2] 5b ef [2] 70 c3 [2] 5e e1 [2] 4a fa [2] 45 e0 [2] 5b fd [2] 59 fc [2] 42 fa [2] 5e fd [2] 42 d2 }

  condition:
    any of them
}