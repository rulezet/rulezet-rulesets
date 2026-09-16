rule TTP_XOR_QUAD_CurrentVersionRun_884d {
  strings:
    $key_884d = { db 22 [2] ff 2c [2] d4 00 [2] fa 22 [2] ee 39 [2] e1 23 [2] ff 3e [2] fd 3f [2] e6 39 [2] fa 3e [2] e6 11 }

  condition:
    any of them
}