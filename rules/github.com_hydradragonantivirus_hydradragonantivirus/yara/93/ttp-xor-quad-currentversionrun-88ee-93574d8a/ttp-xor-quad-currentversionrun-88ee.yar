rule TTP_XOR_QUAD_CurrentVersionRun_88ee {
  strings:
    $key_88ee = { db 81 [2] ff 8f [2] d4 a3 [2] fa 81 [2] ee 9a [2] e1 80 [2] ff 9d [2] fd 9c [2] e6 9a [2] fa 9d [2] e6 b2 }

  condition:
    any of them
}