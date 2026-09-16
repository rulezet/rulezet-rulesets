rule TTP_XOR_QUAD_CurrentVersionRun_8855 {
  strings:
    $key_8855 = { db 3a [2] ff 34 [2] d4 18 [2] fa 3a [2] ee 21 [2] e1 3b [2] ff 26 [2] fd 27 [2] e6 21 [2] fa 26 [2] e6 09 }

  condition:
    any of them
}