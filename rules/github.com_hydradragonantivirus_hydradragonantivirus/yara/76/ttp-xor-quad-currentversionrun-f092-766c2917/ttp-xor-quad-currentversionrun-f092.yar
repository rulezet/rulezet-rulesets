rule TTP_XOR_QUAD_CurrentVersionRun_f092 {
  strings:
    $key_f092 = { a3 fd [2] 87 f3 [2] ac df [2] 82 fd [2] 96 e6 [2] 99 fc [2] 87 e1 [2] 85 e0 [2] 9e e6 [2] 82 e1 [2] 9e ce }

  condition:
    any of them
}