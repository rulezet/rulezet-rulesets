rule TTP_XOR_QUAD_CurrentVersionRun_882f {
  strings:
    $key_882f = { db 40 [2] ff 4e [2] d4 62 [2] fa 40 [2] ee 5b [2] e1 41 [2] ff 5c [2] fd 5d [2] e6 5b [2] fa 5c [2] e6 73 }

  condition:
    any of them
}