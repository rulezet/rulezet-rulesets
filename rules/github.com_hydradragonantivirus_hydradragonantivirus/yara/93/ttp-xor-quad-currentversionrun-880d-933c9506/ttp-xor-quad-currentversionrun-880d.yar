rule TTP_XOR_QUAD_CurrentVersionRun_880d {
  strings:
    $key_880d = { db 62 [2] ff 6c [2] d4 40 [2] fa 62 [2] ee 79 [2] e1 63 [2] ff 7e [2] fd 7f [2] e6 79 [2] fa 7e [2] e6 51 }

  condition:
    any of them
}