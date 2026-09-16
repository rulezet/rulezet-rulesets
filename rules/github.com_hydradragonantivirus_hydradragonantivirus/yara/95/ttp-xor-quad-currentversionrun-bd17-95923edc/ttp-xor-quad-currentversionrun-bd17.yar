rule TTP_XOR_QUAD_CurrentVersionRun_bd17 {
  strings:
    $key_bd17 = { ee 78 [2] ca 76 [2] e1 5a [2] cf 78 [2] db 63 [2] d4 79 [2] ca 64 [2] c8 65 [2] d3 63 [2] cf 64 [2] d3 4b }

  condition:
    any of them
}