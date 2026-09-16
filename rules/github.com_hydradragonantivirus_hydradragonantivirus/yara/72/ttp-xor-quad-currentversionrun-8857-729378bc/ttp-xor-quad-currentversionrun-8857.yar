rule TTP_XOR_QUAD_CurrentVersionRun_8857 {
  strings:
    $key_8857 = { db 38 [2] ff 36 [2] d4 1a [2] fa 38 [2] ee 23 [2] e1 39 [2] ff 24 [2] fd 25 [2] e6 23 [2] fa 24 [2] e6 0b }

  condition:
    any of them
}