rule TTP_XOR_QUAD_CurrentVersionRun_6092 {
  strings:
    $key_6092 = { 33 fd [2] 17 f3 [2] 3c df [2] 12 fd [2] 06 e6 [2] 09 fc [2] 17 e1 [2] 15 e0 [2] 0e e6 [2] 12 e1 [2] 0e ce }

  condition:
    any of them
}