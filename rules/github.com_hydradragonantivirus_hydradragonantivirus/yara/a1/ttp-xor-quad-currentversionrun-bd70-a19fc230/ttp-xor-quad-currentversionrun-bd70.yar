rule TTP_XOR_QUAD_CurrentVersionRun_bd70 {
  strings:
    $key_bd70 = { ee 1f [2] ca 11 [2] e1 3d [2] cf 1f [2] db 04 [2] d4 1e [2] ca 03 [2] c8 02 [2] d3 04 [2] cf 03 [2] d3 2c }

  condition:
    any of them
}