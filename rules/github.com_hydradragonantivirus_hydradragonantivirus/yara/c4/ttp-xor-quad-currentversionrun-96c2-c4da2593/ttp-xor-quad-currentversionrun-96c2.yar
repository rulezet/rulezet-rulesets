rule TTP_XOR_QUAD_CurrentVersionRun_96c2 {
  strings:
    $key_96c2 = { c5 ad [2] e1 a3 [2] ca 8f [2] e4 ad [2] f0 b6 [2] ff ac [2] e1 b1 [2] e3 b0 [2] f8 b6 [2] e4 b1 [2] f8 9e }

  condition:
    any of them
}