rule TTP_XOR_QUAD_CurrentVersionRun_a792 {
  strings:
    $key_a792 = { f4 fd [2] d0 f3 [2] fb df [2] d5 fd [2] c1 e6 [2] ce fc [2] d0 e1 [2] d2 e0 [2] c9 e6 [2] d5 e1 [2] c9 ce }

  condition:
    any of them
}