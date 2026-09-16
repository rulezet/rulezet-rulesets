rule TTP_XOR_QUAD_CurrentVersionRun_88ef {
  strings:
    $key_88ef = { db 80 [2] ff 8e [2] d4 a2 [2] fa 80 [2] ee 9b [2] e1 81 [2] ff 9c [2] fd 9d [2] e6 9b [2] fa 9c [2] e6 b3 }

  condition:
    any of them
}