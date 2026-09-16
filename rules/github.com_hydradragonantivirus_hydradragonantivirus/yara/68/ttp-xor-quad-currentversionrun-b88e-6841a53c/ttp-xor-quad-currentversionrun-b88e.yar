rule TTP_XOR_QUAD_CurrentVersionRun_b88e {
  strings:
    $key_b88e = { eb e1 [2] cf ef [2] e4 c3 [2] ca e1 [2] de fa [2] d1 e0 [2] cf fd [2] cd fc [2] d6 fa [2] ca fd [2] d6 d2 }

  condition:
    any of them
}