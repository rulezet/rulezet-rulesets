rule TTP_XOR_QUAD_CurrentVersionRun_bd5b {
  strings:
    $key_bd5b = { ee 34 [2] ca 3a [2] e1 16 [2] cf 34 [2] db 2f [2] d4 35 [2] ca 28 [2] c8 29 [2] d3 2f [2] cf 28 [2] d3 07 }

  condition:
    any of them
}