rule TTP_XOR_QUAD_CurrentVersionRun_198e {
  strings:
    $key_198e = { 4a e1 [2] 6e ef [2] 45 c3 [2] 6b e1 [2] 7f fa [2] 70 e0 [2] 6e fd [2] 6c fc [2] 77 fa [2] 6b fd [2] 77 d2 }

  condition:
    any of them
}