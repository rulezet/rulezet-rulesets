rule TTP_XOR_QUAD_CurrentVersionRun_8840 {
  strings:
    $key_8840 = { db 2f [2] ff 21 [2] d4 0d [2] fa 2f [2] ee 34 [2] e1 2e [2] ff 33 [2] fd 32 [2] e6 34 [2] fa 33 [2] e6 1c }

  condition:
    any of them
}