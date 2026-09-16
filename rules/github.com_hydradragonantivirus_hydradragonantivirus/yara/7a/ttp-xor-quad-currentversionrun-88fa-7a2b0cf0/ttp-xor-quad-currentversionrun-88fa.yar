rule TTP_XOR_QUAD_CurrentVersionRun_88fa {
  strings:
    $key_88fa = { db 95 [2] ff 9b [2] d4 b7 [2] fa 95 [2] ee 8e [2] e1 94 [2] ff 89 [2] fd 88 [2] e6 8e [2] fa 89 [2] e6 a6 }

  condition:
    any of them
}