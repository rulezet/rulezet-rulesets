rule TTP_XOR_QUAD_CurrentVersionRun_bd39 {
  strings:
    $key_bd39 = { ee 56 [2] ca 58 [2] e1 74 [2] cf 56 [2] db 4d [2] d4 57 [2] ca 4a [2] c8 4b [2] d3 4d [2] cf 4a [2] d3 65 }

  condition:
    any of them
}