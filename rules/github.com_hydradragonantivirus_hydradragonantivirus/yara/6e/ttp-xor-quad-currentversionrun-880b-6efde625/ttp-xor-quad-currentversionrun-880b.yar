rule TTP_XOR_QUAD_CurrentVersionRun_880b {
  strings:
    $key_880b = { db 64 [2] ff 6a [2] d4 46 [2] fa 64 [2] ee 7f [2] e1 65 [2] ff 78 [2] fd 79 [2] e6 7f [2] fa 78 [2] e6 57 }

  condition:
    any of them
}