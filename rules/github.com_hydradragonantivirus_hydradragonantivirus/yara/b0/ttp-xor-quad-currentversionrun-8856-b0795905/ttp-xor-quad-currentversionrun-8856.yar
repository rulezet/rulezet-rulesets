rule TTP_XOR_QUAD_CurrentVersionRun_8856 {
  strings:
    $key_8856 = { db 39 [2] ff 37 [2] d4 1b [2] fa 39 [2] ee 22 [2] e1 38 [2] ff 25 [2] fd 24 [2] e6 22 [2] fa 25 [2] e6 0a }

  condition:
    any of them
}