rule TTP_XOR_QUAD_CurrentVersionRun_886f {
  strings:
    $key_886f = { db 00 [2] ff 0e [2] d4 22 [2] fa 00 [2] ee 1b [2] e1 01 [2] ff 1c [2] fd 1d [2] e6 1b [2] fa 1c [2] e6 33 }

  condition:
    any of them
}