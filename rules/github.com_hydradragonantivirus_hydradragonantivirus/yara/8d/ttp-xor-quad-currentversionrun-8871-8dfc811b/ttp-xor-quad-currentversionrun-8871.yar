rule TTP_XOR_QUAD_CurrentVersionRun_8871 {
  strings:
    $key_8871 = { db 1e [2] ff 10 [2] d4 3c [2] fa 1e [2] ee 05 [2] e1 1f [2] ff 02 [2] fd 03 [2] e6 05 [2] fa 02 [2] e6 2d }

  condition:
    any of them
}