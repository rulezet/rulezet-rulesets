rule TTP_XOR_QUAD_CurrentVersionRun_8804 {
  strings:
    $key_8804 = { db 6b [2] ff 65 [2] d4 49 [2] fa 6b [2] ee 70 [2] e1 6a [2] ff 77 [2] fd 76 [2] e6 70 [2] fa 77 [2] e6 58 }

  condition:
    any of them
}