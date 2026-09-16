rule TTP_XOR_QUAD_CurrentVersionRun_bd34 {
  strings:
    $key_bd34 = { ee 5b [2] ca 55 [2] e1 79 [2] cf 5b [2] db 40 [2] d4 5a [2] ca 47 [2] c8 46 [2] d3 40 [2] cf 47 [2] d3 68 }

  condition:
    any of them
}