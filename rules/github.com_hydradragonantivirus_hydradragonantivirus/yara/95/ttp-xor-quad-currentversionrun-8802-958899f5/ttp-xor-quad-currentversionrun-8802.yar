rule TTP_XOR_QUAD_CurrentVersionRun_8802 {
  strings:
    $key_8802 = { db 6d [2] ff 63 [2] d4 4f [2] fa 6d [2] ee 76 [2] e1 6c [2] ff 71 [2] fd 70 [2] e6 76 [2] fa 71 [2] e6 5e }

  condition:
    any of them
}