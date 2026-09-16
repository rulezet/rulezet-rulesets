rule TTP_XOR_QUAD_CurrentVersionRun_88f4 {
  strings:
    $key_88f4 = { db 9b [2] ff 95 [2] d4 b9 [2] fa 9b [2] ee 80 [2] e1 9a [2] ff 87 [2] fd 86 [2] e6 80 [2] fa 87 [2] e6 a8 }

  condition:
    any of them
}