rule TTP_XOR_QUAD_CurrentVersionRun_886a {
  strings:
    $key_886a = { db 05 [2] ff 0b [2] d4 27 [2] fa 05 [2] ee 1e [2] e1 04 [2] ff 19 [2] fd 18 [2] e6 1e [2] fa 19 [2] e6 36 }

  condition:
    any of them
}