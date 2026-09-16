rule TTP_XOR_QUAD_CurrentVersionRun_87c2 {
  strings:
    $key_87c2 = { d4 ad [2] f0 a3 [2] db 8f [2] f5 ad [2] e1 b6 [2] ee ac [2] f0 b1 [2] f2 b0 [2] e9 b6 [2] f5 b1 [2] e9 9e }

  condition:
    any of them
}