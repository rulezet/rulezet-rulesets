rule TTP_XOR_QUAD_CurrentVersionRun_88df {
  strings:
    $key_88df = { db b0 [2] ff be [2] d4 92 [2] fa b0 [2] ee ab [2] e1 b1 [2] ff ac [2] fd ad [2] e6 ab [2] fa ac [2] e6 83 }

  condition:
    any of them
}