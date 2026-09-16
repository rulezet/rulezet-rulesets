rule TTP_XOR_QUAD_CurrentVersionRun_885c {
  strings:
    $key_885c = { db 33 [2] ff 3d [2] d4 11 [2] fa 33 [2] ee 28 [2] e1 32 [2] ff 2f [2] fd 2e [2] e6 28 [2] fa 2f [2] e6 00 }

  condition:
    any of them
}