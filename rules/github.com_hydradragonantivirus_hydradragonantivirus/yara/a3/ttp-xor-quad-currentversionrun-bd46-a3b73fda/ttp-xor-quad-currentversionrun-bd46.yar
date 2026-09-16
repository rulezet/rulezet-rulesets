rule TTP_XOR_QUAD_CurrentVersionRun_bd46 {
  strings:
    $key_bd46 = { ee 29 [2] ca 27 [2] e1 0b [2] cf 29 [2] db 32 [2] d4 28 [2] ca 35 [2] c8 34 [2] d3 32 [2] cf 35 [2] d3 1a }

  condition:
    any of them
}