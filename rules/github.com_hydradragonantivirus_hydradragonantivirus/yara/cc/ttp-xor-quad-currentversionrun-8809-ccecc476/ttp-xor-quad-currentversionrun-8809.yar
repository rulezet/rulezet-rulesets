rule TTP_XOR_QUAD_CurrentVersionRun_8809 {
  strings:
    $key_8809 = { db 66 [2] ff 68 [2] d4 44 [2] fa 66 [2] ee 7d [2] e1 67 [2] ff 7a [2] fd 7b [2] e6 7d [2] fa 7a [2] e6 55 }

  condition:
    any of them
}