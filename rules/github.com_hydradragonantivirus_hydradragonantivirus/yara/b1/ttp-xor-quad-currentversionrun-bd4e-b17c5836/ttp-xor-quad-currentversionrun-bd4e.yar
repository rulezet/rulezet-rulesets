rule TTP_XOR_QUAD_CurrentVersionRun_bd4e {
  strings:
    $key_bd4e = { ee 21 [2] ca 2f [2] e1 03 [2] cf 21 [2] db 3a [2] d4 20 [2] ca 3d [2] c8 3c [2] d3 3a [2] cf 3d [2] d3 12 }

  condition:
    any of them
}