rule TTP_XOR_QUAD_CurrentVersionRun_8830 {
  strings:
    $key_8830 = { db 5f [2] ff 51 [2] d4 7d [2] fa 5f [2] ee 44 [2] e1 5e [2] ff 43 [2] fd 42 [2] e6 44 [2] fa 43 [2] e6 6c }

  condition:
    any of them
}