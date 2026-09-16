rule TTP_XOR_QUAD_CurrentVersionRun_8815 {
  strings:
    $key_8815 = { db 7a [2] ff 74 [2] d4 58 [2] fa 7a [2] ee 61 [2] e1 7b [2] ff 66 [2] fd 67 [2] e6 61 [2] fa 66 [2] e6 49 }

  condition:
    any of them
}