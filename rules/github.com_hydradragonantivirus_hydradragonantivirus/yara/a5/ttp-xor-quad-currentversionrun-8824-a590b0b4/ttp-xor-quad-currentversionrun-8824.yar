rule TTP_XOR_QUAD_CurrentVersionRun_8824 {
  strings:
    $key_8824 = { db 4b [2] ff 45 [2] d4 69 [2] fa 4b [2] ee 50 [2] e1 4a [2] ff 57 [2] fd 56 [2] e6 50 [2] fa 57 [2] e6 78 }

  condition:
    any of them
}