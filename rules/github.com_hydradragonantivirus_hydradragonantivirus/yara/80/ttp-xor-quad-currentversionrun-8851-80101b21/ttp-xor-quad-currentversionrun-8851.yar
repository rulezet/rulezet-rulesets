rule TTP_XOR_QUAD_CurrentVersionRun_8851 {
  strings:
    $key_8851 = { db 3e [2] ff 30 [2] d4 1c [2] fa 3e [2] ee 25 [2] e1 3f [2] ff 22 [2] fd 23 [2] e6 25 [2] fa 22 [2] e6 0d }

  condition:
    any of them
}