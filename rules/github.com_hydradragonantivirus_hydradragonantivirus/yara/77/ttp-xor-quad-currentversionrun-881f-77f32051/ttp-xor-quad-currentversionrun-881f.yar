rule TTP_XOR_QUAD_CurrentVersionRun_881f {
  strings:
    $key_881f = { db 70 [2] ff 7e [2] d4 52 [2] fa 70 [2] ee 6b [2] e1 71 [2] ff 6c [2] fd 6d [2] e6 6b [2] fa 6c [2] e6 43 }

  condition:
    any of them
}