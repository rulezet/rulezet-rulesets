rule TTP_XOR_QUAD_CurrentVersionRun_8833 {
  strings:
    $key_8833 = { db 5c [2] ff 52 [2] d4 7e [2] fa 5c [2] ee 47 [2] e1 5d [2] ff 40 [2] fd 41 [2] e6 47 [2] fa 40 [2] e6 6f }

  condition:
    any of them
}