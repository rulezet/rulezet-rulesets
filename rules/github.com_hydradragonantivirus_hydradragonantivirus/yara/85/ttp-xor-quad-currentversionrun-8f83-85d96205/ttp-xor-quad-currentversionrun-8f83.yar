rule TTP_XOR_QUAD_CurrentVersionRun_8f83 {
  strings:
    $key_8f83 = { dc ec [2] f8 e2 [2] d3 ce [2] fd ec [2] e9 f7 [2] e6 ed [2] f8 f0 [2] fa f1 [2] e1 f7 [2] fd f0 [2] e1 df }

  condition:
    any of them
}