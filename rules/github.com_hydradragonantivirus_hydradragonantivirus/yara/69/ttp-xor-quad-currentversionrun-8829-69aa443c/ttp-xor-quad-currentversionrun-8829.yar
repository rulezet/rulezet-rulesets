rule TTP_XOR_QUAD_CurrentVersionRun_8829 {
  strings:
    $key_8829 = { db 46 [2] ff 48 [2] d4 64 [2] fa 46 [2] ee 5d [2] e1 47 [2] ff 5a [2] fd 5b [2] e6 5d [2] fa 5a [2] e6 75 }

  condition:
    any of them
}