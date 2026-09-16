rule TTP_XOR_QUAD_CurrentVersionRun_cc8e {
  strings:
    $key_cc8e = { 9f e1 [2] bb ef [2] 90 c3 [2] be e1 [2] aa fa [2] a5 e0 [2] bb fd [2] b9 fc [2] a2 fa [2] be fd [2] a2 d2 }

  condition:
    any of them
}