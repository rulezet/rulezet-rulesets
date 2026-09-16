rule TTP_XOR_QUAD_CurrentVersionRun_8839 {
  strings:
    $key_8839 = { db 56 [2] ff 58 [2] d4 74 [2] fa 56 [2] ee 4d [2] e1 57 [2] ff 4a [2] fd 4b [2] e6 4d [2] fa 4a [2] e6 65 }

  condition:
    any of them
}