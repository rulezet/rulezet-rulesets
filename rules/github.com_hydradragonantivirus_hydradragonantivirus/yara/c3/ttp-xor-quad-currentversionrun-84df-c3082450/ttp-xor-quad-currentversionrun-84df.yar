rule TTP_XOR_QUAD_CurrentVersionRun_84df {
  strings:
    $key_84df = { d7 b0 [2] f3 be [2] d8 92 [2] f6 b0 [2] e2 ab [2] ed b1 [2] f3 ac [2] f1 ad [2] ea ab [2] f6 ac [2] ea 83 }

  condition:
    any of them
}