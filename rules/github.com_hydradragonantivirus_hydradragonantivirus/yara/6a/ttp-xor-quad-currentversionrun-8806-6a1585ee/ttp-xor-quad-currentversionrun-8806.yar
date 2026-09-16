rule TTP_XOR_QUAD_CurrentVersionRun_8806 {
  strings:
    $key_8806 = { db 69 [2] ff 67 [2] d4 4b [2] fa 69 [2] ee 72 [2] e1 68 [2] ff 75 [2] fd 74 [2] e6 72 [2] fa 75 [2] e6 5a }

  condition:
    any of them
}