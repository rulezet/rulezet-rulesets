rule TTP_XOR_QUAD_CurrentVersionRun_8877 {
  strings:
    $key_8877 = { db 18 [2] ff 16 [2] d4 3a [2] fa 18 [2] ee 03 [2] e1 19 [2] ff 04 [2] fd 05 [2] e6 03 [2] fa 04 [2] e6 2b }

  condition:
    any of them
}