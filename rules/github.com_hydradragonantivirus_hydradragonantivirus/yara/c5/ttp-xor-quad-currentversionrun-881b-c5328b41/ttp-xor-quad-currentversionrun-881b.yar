rule TTP_XOR_QUAD_CurrentVersionRun_881b {
  strings:
    $key_881b = { db 74 [2] ff 7a [2] d4 56 [2] fa 74 [2] ee 6f [2] e1 75 [2] ff 68 [2] fd 69 [2] e6 6f [2] fa 68 [2] e6 47 }

  condition:
    any of them
}