rule TTP_XOR_QUAD_CurrentVersionRun_886b {
  strings:
    $key_886b = { db 04 [2] ff 0a [2] d4 26 [2] fa 04 [2] ee 1f [2] e1 05 [2] ff 18 [2] fd 19 [2] e6 1f [2] fa 18 [2] e6 37 }

  condition:
    any of them
}