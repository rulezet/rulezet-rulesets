rule TTP_XOR_QUAD_CurrentVersionRun_889f {
  strings:
    $key_889f = { db f0 [2] ff fe [2] d4 d2 [2] fa f0 [2] ee eb [2] e1 f1 [2] ff ec [2] fd ed [2] e6 eb [2] fa ec [2] e6 c3 }

  condition:
    any of them
}