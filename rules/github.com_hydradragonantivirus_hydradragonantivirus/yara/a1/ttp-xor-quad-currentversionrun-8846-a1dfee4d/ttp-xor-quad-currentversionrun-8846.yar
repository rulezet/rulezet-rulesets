rule TTP_XOR_QUAD_CurrentVersionRun_8846 {
  strings:
    $key_8846 = { db 29 [2] ff 27 [2] d4 0b [2] fa 29 [2] ee 32 [2] e1 28 [2] ff 35 [2] fd 34 [2] e6 32 [2] fa 35 [2] e6 1a }

  condition:
    any of them
}