rule TTP_XOR_QUAD_CurrentVersionRun_8873 {
  strings:
    $key_8873 = { db 1c [2] ff 12 [2] d4 3e [2] fa 1c [2] ee 07 [2] e1 1d [2] ff 00 [2] fd 01 [2] e6 07 [2] fa 00 [2] e6 2f }

  condition:
    any of them
}