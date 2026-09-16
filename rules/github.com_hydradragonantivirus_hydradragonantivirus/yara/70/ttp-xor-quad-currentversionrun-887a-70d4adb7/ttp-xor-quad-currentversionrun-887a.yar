rule TTP_XOR_QUAD_CurrentVersionRun_887a {
  strings:
    $key_887a = { db 15 [2] ff 1b [2] d4 37 [2] fa 15 [2] ee 0e [2] e1 14 [2] ff 09 [2] fd 08 [2] e6 0e [2] fa 09 [2] e6 26 }

  condition:
    any of them
}