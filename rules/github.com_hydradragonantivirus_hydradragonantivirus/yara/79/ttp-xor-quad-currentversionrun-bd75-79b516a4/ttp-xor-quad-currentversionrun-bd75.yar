rule TTP_XOR_QUAD_CurrentVersionRun_bd75 {
  strings:
    $key_bd75 = { ee 1a [2] ca 14 [2] e1 38 [2] cf 1a [2] db 01 [2] d4 1b [2] ca 06 [2] c8 07 [2] d3 01 [2] cf 06 [2] d3 29 }

  condition:
    any of them
}