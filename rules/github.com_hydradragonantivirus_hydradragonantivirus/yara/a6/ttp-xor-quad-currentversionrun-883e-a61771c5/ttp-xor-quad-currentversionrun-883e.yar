rule TTP_XOR_QUAD_CurrentVersionRun_883e {
  strings:
    $key_883e = { db 51 [2] ff 5f [2] d4 73 [2] fa 51 [2] ee 4a [2] e1 50 [2] ff 4d [2] fd 4c [2] e6 4a [2] fa 4d [2] e6 62 }

  condition:
    any of them
}