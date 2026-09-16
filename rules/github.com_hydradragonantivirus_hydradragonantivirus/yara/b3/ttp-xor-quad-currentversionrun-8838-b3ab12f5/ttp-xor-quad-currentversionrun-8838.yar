rule TTP_XOR_QUAD_CurrentVersionRun_8838 {
  strings:
    $key_8838 = { db 57 [2] ff 59 [2] d4 75 [2] fa 57 [2] ee 4c [2] e1 56 [2] ff 4b [2] fd 4a [2] e6 4c [2] fa 4b [2] e6 64 }

  condition:
    any of them
}