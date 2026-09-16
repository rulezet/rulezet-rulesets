rule TTP_XOR_QUAD_CurrentVersionRun_8843 {
  strings:
    $key_8843 = { db 2c [2] ff 22 [2] d4 0e [2] fa 2c [2] ee 37 [2] e1 2d [2] ff 30 [2] fd 31 [2] e6 37 [2] fa 30 [2] e6 1f }

  condition:
    any of them
}