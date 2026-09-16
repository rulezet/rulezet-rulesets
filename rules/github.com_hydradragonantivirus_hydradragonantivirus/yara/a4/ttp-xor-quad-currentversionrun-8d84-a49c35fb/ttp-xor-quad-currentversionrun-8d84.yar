rule TTP_XOR_QUAD_CurrentVersionRun_8d84 {
  strings:
    $key_8d84 = { de eb [2] fa e5 [2] d1 c9 [2] ff eb [2] eb f0 [2] e4 ea [2] fa f7 [2] f8 f6 [2] e3 f0 [2] ff f7 [2] e3 d8 }

  condition:
    any of them
}