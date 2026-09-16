rule TTP_XOR_QUAD_CurrentVersionRun_8811 {
  strings:
    $key_8811 = { db 7e [2] ff 70 [2] d4 5c [2] fa 7e [2] ee 65 [2] e1 7f [2] ff 62 [2] fd 63 [2] e6 65 [2] fa 62 [2] e6 4d }

  condition:
    any of them
}