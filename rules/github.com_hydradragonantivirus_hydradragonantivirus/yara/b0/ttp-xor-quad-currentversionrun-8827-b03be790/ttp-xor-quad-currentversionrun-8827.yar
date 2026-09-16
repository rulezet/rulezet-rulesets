rule TTP_XOR_QUAD_CurrentVersionRun_8827 {
  strings:
    $key_8827 = { db 48 [2] ff 46 [2] d4 6a [2] fa 48 [2] ee 53 [2] e1 49 [2] ff 54 [2] fd 55 [2] e6 53 [2] fa 54 [2] e6 7b }

  condition:
    any of them
}