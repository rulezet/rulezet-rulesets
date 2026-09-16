rule TTP_XOR_QUAD_CurrentVersionRun_889e {
  strings:
    $key_889e = { db f1 [2] ff ff [2] d4 d3 [2] fa f1 [2] ee ea [2] e1 f0 [2] ff ed [2] fd ec [2] e6 ea [2] fa ed [2] e6 c2 }

  condition:
    any of them
}