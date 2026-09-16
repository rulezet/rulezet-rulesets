rule TTP_XOR_QUAD_CurrentVersionRun_8810 {
  strings:
    $key_8810 = { db 7f [2] ff 71 [2] d4 5d [2] fa 7f [2] ee 64 [2] e1 7e [2] ff 63 [2] fd 62 [2] e6 64 [2] fa 63 [2] e6 4c }

  condition:
    any of them
}