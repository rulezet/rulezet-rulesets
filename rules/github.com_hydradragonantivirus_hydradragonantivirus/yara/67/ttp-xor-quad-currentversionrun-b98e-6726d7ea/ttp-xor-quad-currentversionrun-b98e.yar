rule TTP_XOR_QUAD_CurrentVersionRun_b98e {
  strings:
    $key_b98e = { ea e1 [2] ce ef [2] e5 c3 [2] cb e1 [2] df fa [2] d0 e0 [2] ce fd [2] cc fc [2] d7 fa [2] cb fd [2] d7 d2 }

  condition:
    any of them
}