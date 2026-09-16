rule TTP_XOR_QUAD_CurrentVersionRun_8872 {
  strings:
    $key_8872 = { db 1d [2] ff 13 [2] d4 3f [2] fa 1d [2] ee 06 [2] e1 1c [2] ff 01 [2] fd 00 [2] e6 06 [2] fa 01 [2] e6 2e }

  condition:
    any of them
}