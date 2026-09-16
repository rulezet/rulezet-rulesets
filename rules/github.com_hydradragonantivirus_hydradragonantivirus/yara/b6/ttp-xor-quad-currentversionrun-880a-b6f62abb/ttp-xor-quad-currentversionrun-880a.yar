rule TTP_XOR_QUAD_CurrentVersionRun_880a {
  strings:
    $key_880a = { db 65 [2] ff 6b [2] d4 47 [2] fa 65 [2] ee 7e [2] e1 64 [2] ff 79 [2] fd 78 [2] e6 7e [2] fa 79 [2] e6 56 }

  condition:
    any of them
}