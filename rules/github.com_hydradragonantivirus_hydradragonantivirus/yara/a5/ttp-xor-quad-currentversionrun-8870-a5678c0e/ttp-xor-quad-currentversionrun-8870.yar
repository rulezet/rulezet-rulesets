rule TTP_XOR_QUAD_CurrentVersionRun_8870 {
  strings:
    $key_8870 = { db 1f [2] ff 11 [2] d4 3d [2] fa 1f [2] ee 04 [2] e1 1e [2] ff 03 [2] fd 02 [2] e6 04 [2] fa 03 [2] e6 2c }

  condition:
    any of them
}