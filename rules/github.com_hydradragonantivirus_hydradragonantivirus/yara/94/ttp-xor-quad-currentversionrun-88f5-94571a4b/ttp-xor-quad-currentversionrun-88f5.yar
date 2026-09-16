rule TTP_XOR_QUAD_CurrentVersionRun_88f5 {
  strings:
    $key_88f5 = { db 9a [2] ff 94 [2] d4 b8 [2] fa 9a [2] ee 81 [2] e1 9b [2] ff 86 [2] fd 87 [2] e6 81 [2] fa 86 [2] e6 a9 }

  condition:
    any of them
}