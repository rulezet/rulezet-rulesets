rule TTP_XOR_QUAD_CurrentVersionRun_8859 {
  strings:
    $key_8859 = { db 36 [2] ff 38 [2] d4 14 [2] fa 36 [2] ee 2d [2] e1 37 [2] ff 2a [2] fd 2b [2] e6 2d [2] fa 2a [2] e6 05 }

  condition:
    any of them
}