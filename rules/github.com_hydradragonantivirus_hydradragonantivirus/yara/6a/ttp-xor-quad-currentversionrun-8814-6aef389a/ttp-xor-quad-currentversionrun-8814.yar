rule TTP_XOR_QUAD_CurrentVersionRun_8814 {
  strings:
    $key_8814 = { db 7b [2] ff 75 [2] d4 59 [2] fa 7b [2] ee 60 [2] e1 7a [2] ff 67 [2] fd 66 [2] e6 60 [2] fa 67 [2] e6 48 }

  condition:
    any of them
}