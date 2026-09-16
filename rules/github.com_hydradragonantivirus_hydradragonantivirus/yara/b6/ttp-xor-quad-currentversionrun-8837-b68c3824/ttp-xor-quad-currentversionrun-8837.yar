rule TTP_XOR_QUAD_CurrentVersionRun_8837 {
  strings:
    $key_8837 = { db 58 [2] ff 56 [2] d4 7a [2] fa 58 [2] ee 43 [2] e1 59 [2] ff 44 [2] fd 45 [2] e6 43 [2] fa 44 [2] e6 6b }

  condition:
    any of them
}