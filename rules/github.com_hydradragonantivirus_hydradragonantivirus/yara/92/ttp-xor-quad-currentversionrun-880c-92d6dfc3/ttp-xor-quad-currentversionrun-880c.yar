rule TTP_XOR_QUAD_CurrentVersionRun_880c {
  strings:
    $key_880c = { db 63 [2] ff 6d [2] d4 41 [2] fa 63 [2] ee 78 [2] e1 62 [2] ff 7f [2] fd 7e [2] e6 78 [2] fa 7f [2] e6 50 }

  condition:
    any of them
}