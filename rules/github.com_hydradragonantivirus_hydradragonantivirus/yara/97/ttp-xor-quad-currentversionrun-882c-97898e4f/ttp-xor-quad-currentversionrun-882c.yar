rule TTP_XOR_QUAD_CurrentVersionRun_882c {
  strings:
    $key_882c = { db 43 [2] ff 4d [2] d4 61 [2] fa 43 [2] ee 58 [2] e1 42 [2] ff 5f [2] fd 5e [2] e6 58 [2] fa 5f [2] e6 70 }

  condition:
    any of them
}