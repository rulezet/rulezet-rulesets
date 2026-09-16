rule TTP_XOR_QUAD_CurrentVersionRun_881d {
  strings:
    $key_881d = { db 72 [2] ff 7c [2] d4 50 [2] fa 72 [2] ee 69 [2] e1 73 [2] ff 6e [2] fd 6f [2] e6 69 [2] fa 6e [2] e6 41 }

  condition:
    any of them
}