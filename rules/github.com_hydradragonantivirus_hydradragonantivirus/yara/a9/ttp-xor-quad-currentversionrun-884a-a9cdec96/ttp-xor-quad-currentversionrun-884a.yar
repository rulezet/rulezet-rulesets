rule TTP_XOR_QUAD_CurrentVersionRun_884a {
  strings:
    $key_884a = { db 25 [2] ff 2b [2] d4 07 [2] fa 25 [2] ee 3e [2] e1 24 [2] ff 39 [2] fd 38 [2] e6 3e [2] fa 39 [2] e6 16 }

  condition:
    any of them
}