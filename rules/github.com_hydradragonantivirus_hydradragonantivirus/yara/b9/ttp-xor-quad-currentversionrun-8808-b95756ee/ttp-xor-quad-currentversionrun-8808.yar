rule TTP_XOR_QUAD_CurrentVersionRun_8808 {
  strings:
    $key_8808 = { db 67 [2] ff 69 [2] d4 45 [2] fa 67 [2] ee 7c [2] e1 66 [2] ff 7b [2] fd 7a [2] e6 7c [2] fa 7b [2] e6 54 }

  condition:
    any of them
}