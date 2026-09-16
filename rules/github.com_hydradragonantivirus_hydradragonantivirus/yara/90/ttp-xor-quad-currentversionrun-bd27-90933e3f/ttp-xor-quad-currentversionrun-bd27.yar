rule TTP_XOR_QUAD_CurrentVersionRun_bd27 {
  strings:
    $key_bd27 = { ee 48 [2] ca 46 [2] e1 6a [2] cf 48 [2] db 53 [2] d4 49 [2] ca 54 [2] c8 55 [2] d3 53 [2] cf 54 [2] d3 7b }

  condition:
    any of them
}