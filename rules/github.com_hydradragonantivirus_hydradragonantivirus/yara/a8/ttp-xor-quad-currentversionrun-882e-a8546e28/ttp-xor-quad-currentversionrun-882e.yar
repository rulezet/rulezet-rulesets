rule TTP_XOR_QUAD_CurrentVersionRun_882e {
  strings:
    $key_882e = { db 41 [2] ff 4f [2] d4 63 [2] fa 41 [2] ee 5a [2] e1 40 [2] ff 5d [2] fd 5c [2] e6 5a [2] fa 5d [2] e6 72 }

  condition:
    any of them
}