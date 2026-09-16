rule TTP_XOR_QUAD_CurrentVersionRun_885a {
  strings:
    $key_885a = { db 35 [2] ff 3b [2] d4 17 [2] fa 35 [2] ee 2e [2] e1 34 [2] ff 29 [2] fd 28 [2] e6 2e [2] fa 29 [2] e6 06 }

  condition:
    any of them
}