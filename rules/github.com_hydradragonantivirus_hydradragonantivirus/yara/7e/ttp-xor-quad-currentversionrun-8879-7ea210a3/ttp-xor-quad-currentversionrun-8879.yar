rule TTP_XOR_QUAD_CurrentVersionRun_8879 {
  strings:
    $key_8879 = { db 16 [2] ff 18 [2] d4 34 [2] fa 16 [2] ee 0d [2] e1 17 [2] ff 0a [2] fd 0b [2] e6 0d [2] fa 0a [2] e6 25 }

  condition:
    any of them
}