rule TTP_XOR_QUAD_CurrentVersionRun_84c2 {
  strings:
    $key_84c2 = { d7 ad [2] f3 a3 [2] d8 8f [2] f6 ad [2] e2 b6 [2] ed ac [2] f3 b1 [2] f1 b0 [2] ea b6 [2] f6 b1 [2] ea 9e }

  condition:
    any of them
}