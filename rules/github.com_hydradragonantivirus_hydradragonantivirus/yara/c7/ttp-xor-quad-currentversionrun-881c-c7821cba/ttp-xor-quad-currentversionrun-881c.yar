rule TTP_XOR_QUAD_CurrentVersionRun_881c {
  strings:
    $key_881c = { db 73 [2] ff 7d [2] d4 51 [2] fa 73 [2] ee 68 [2] e1 72 [2] ff 6f [2] fd 6e [2] e6 68 [2] fa 6f [2] e6 40 }

  condition:
    any of them
}