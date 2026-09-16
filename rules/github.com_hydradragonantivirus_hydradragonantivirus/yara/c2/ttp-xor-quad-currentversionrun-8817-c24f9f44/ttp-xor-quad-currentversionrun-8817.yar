rule TTP_XOR_QUAD_CurrentVersionRun_8817 {
  strings:
    $key_8817 = { db 78 [2] ff 76 [2] d4 5a [2] fa 78 [2] ee 63 [2] e1 79 [2] ff 64 [2] fd 65 [2] e6 63 [2] fa 64 [2] e6 4b }

  condition:
    any of them
}