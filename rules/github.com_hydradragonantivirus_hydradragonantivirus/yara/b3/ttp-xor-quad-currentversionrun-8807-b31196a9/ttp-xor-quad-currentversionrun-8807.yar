rule TTP_XOR_QUAD_CurrentVersionRun_8807 {
  strings:
    $key_8807 = { db 68 [2] ff 66 [2] d4 4a [2] fa 68 [2] ee 73 [2] e1 69 [2] ff 74 [2] fd 75 [2] e6 73 [2] fa 74 [2] e6 5b }

  condition:
    any of them
}