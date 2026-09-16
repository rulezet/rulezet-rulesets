rule TTP_XOR_QUAD_CurrentVersionRun_88f7 {
  strings:
    $key_88f7 = { db 98 [2] ff 96 [2] d4 ba [2] fa 98 [2] ee 83 [2] e1 99 [2] ff 84 [2] fd 85 [2] e6 83 [2] fa 84 [2] e6 ab }

  condition:
    any of them
}