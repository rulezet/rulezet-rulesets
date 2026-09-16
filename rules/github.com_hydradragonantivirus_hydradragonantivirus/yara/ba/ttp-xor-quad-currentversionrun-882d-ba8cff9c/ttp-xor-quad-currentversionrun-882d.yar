rule TTP_XOR_QUAD_CurrentVersionRun_882d {
  strings:
    $key_882d = { db 42 [2] ff 4c [2] d4 60 [2] fa 42 [2] ee 59 [2] e1 43 [2] ff 5e [2] fd 5f [2] e6 59 [2] fa 5e [2] e6 71 }

  condition:
    any of them
}