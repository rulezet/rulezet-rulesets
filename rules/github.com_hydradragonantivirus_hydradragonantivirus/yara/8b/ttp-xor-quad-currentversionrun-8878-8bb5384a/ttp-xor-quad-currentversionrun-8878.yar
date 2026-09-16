rule TTP_XOR_QUAD_CurrentVersionRun_8878 {
  strings:
    $key_8878 = { db 17 [2] ff 19 [2] d4 35 [2] fa 17 [2] ee 0c [2] e1 16 [2] ff 0b [2] fd 0a [2] e6 0c [2] fa 0b [2] e6 24 }

  condition:
    any of them
}