rule TTP_XOR_QUAD_CurrentVersionRun_8864 {
  strings:
    $key_8864 = { db 0b [2] ff 05 [2] d4 29 [2] fa 0b [2] ee 10 [2] e1 0a [2] ff 17 [2] fd 16 [2] e6 10 [2] fa 17 [2] e6 38 }

  condition:
    any of them
}