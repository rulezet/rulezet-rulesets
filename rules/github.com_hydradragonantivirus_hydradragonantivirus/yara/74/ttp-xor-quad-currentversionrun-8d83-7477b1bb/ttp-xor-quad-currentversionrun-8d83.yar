rule TTP_XOR_QUAD_CurrentVersionRun_8d83 {
  strings:
    $key_8d83 = { de ec [2] fa e2 [2] d1 ce [2] ff ec [2] eb f7 [2] e4 ed [2] fa f0 [2] f8 f1 [2] e3 f7 [2] ff f0 [2] e3 df }

  condition:
    any of them
}