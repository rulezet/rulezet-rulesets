rule TTP_XOR_QUAD_CurrentVersionRun_883c {
  strings:
    $key_883c = { db 53 [2] ff 5d [2] d4 71 [2] fa 53 [2] ee 48 [2] e1 52 [2] ff 4f [2] fd 4e [2] e6 48 [2] fa 4f [2] e6 60 }

  condition:
    any of them
}